"""
Advanced Fuzzing Features

This module provides advanced fuzzing capabilities including:
- Payload encoding/transformation
- Payload generators (ranges, patterns)
- Response clustering and similarity analysis
- Grep/Extract rules for data extraction
- WAF/Rate limiting detection
- Recursive parameter discovery
"""

import re
import base64
import html
import hashlib
import urllib.parse
from typing import Any, Dict, List, Optional, Tuple, Set
from dataclasses import dataclass, field, asdict
from enum import Enum
from collections import defaultdict
import difflib
import json


# ============================================================================
# PAYLOAD ENCODING
# ============================================================================

class EncodingType(str, Enum):
    """Available encoding types for payloads."""
    NONE = "none"
    URL = "url"
    DOUBLE_URL = "double_url"
    BASE64 = "base64"
    HTML_ENTITIES = "html_entities"
    HTML_DECIMAL = "html_decimal"
    HTML_HEX = "html_hex"
    UNICODE = "unicode"
    HEX = "hex"
    OCTAL = "octal"
    BINARY = "binary"


def encode_payload(payload: str, encoding: EncodingType) -> str:
    """Encode a payload using the specified encoding type."""
    if encoding == EncodingType.NONE:
        return payload
    elif encoding == EncodingType.URL:
        return urllib.parse.quote(payload, safe='')
    elif encoding == EncodingType.DOUBLE_URL:
        return urllib.parse.quote(urllib.parse.quote(payload, safe=''), safe='')
    elif encoding == EncodingType.BASE64:
        return base64.b64encode(payload.encode()).decode()
    elif encoding == EncodingType.HTML_ENTITIES:
        return html.escape(payload)
    elif encoding == EncodingType.HTML_DECIMAL:
        return ''.join(f'&#{ord(c)};' for c in payload)
    elif encoding == EncodingType.HTML_HEX:
        return ''.join(f'&#x{ord(c):x};' for c in payload)
    elif encoding == EncodingType.UNICODE:
        return ''.join(f'\\u{ord(c):04x}' for c in payload)
    elif encoding == EncodingType.HEX:
        return payload.encode().hex()
    elif encoding == EncodingType.OCTAL:
        return ''.join(f'\\{ord(c):03o}' for c in payload)
    elif encoding == EncodingType.BINARY:
        return ''.join(format(ord(c), '08b') for c in payload)
    return payload


def apply_multiple_encodings(payload: str, encodings: List[EncodingType]) -> str:
    """Apply multiple encodings in sequence."""
    result = payload
    for encoding in encodings:
        result = encode_payload(result, encoding)
    return result


def generate_encoded_variants(payload: str, encodings: List[EncodingType] = None) -> Dict[str, str]:
    """Generate all encoded variants of a payload."""
    if encodings is None:
        encodings = list(EncodingType)
    
    return {
        enc.value: encode_payload(payload, enc)
        for enc in encodings
    }


# ============================================================================
# PAYLOAD TRANSFORMATIONS
# ============================================================================

class TransformationType(str, Enum):
    """Available transformation types for payloads."""
    NONE = "none"
    UPPERCASE = "uppercase"
    LOWERCASE = "lowercase"
    CAPITALIZE = "capitalize"
    REVERSE = "reverse"
    ADD_NULL_BYTE = "add_null_byte"
    ADD_NEWLINE = "add_newline"
    ADD_TAB = "add_tab"
    STRIP_SPACES = "strip_spaces"
    DOUBLE_CHARS = "double_chars"
    CASE_SWAP = "case_swap"
    ADD_PREFIX = "add_prefix"
    ADD_SUFFIX = "add_suffix"


def transform_payload(
    payload: str, 
    transformation: TransformationType,
    prefix: str = "",
    suffix: str = ""
) -> str:
    """Apply a transformation to a payload."""
    if transformation == TransformationType.NONE:
        return payload
    elif transformation == TransformationType.UPPERCASE:
        return payload.upper()
    elif transformation == TransformationType.LOWERCASE:
        return payload.lower()
    elif transformation == TransformationType.CAPITALIZE:
        return payload.capitalize()
    elif transformation == TransformationType.REVERSE:
        return payload[::-1]
    elif transformation == TransformationType.ADD_NULL_BYTE:
        return payload + '\x00'
    elif transformation == TransformationType.ADD_NEWLINE:
        return payload + '\n'
    elif transformation == TransformationType.ADD_TAB:
        return payload + '\t'
    elif transformation == TransformationType.STRIP_SPACES:
        return payload.replace(' ', '')
    elif transformation == TransformationType.DOUBLE_CHARS:
        return ''.join(c*2 for c in payload)
    elif transformation == TransformationType.CASE_SWAP:
        return payload.swapcase()
    elif transformation == TransformationType.ADD_PREFIX:
        return prefix + payload
    elif transformation == TransformationType.ADD_SUFFIX:
        return payload + suffix
    return payload


# ============================================================================
# PAYLOAD GENERATORS
# ============================================================================

@dataclass
class GeneratorConfig:
    """Configuration for payload generators."""
    type: str
    params: Dict[str, Any] = field(default_factory=dict)


def generate_number_range(start: int, end: int, step: int = 1, padding: int = 0) -> List[str]:
    """Generate a range of numbers as payloads."""
    payloads = []
    for i in range(start, end + 1, step):
        if padding > 0:
            payloads.append(str(i).zfill(padding))
        else:
            payloads.append(str(i))
    return payloads


def generate_char_range(start_char: str, end_char: str) -> List[str]:
    """Generate a range of characters as payloads."""
    start_ord = ord(start_char)
    end_ord = ord(end_char)
    return [chr(i) for i in range(start_ord, end_ord + 1)]


def generate_date_range(
    start_date: str,  # Format: YYYY-MM-DD
    end_date: str,
    date_format: str = "%Y-%m-%d"
) -> List[str]:
    """Generate a range of dates as payloads."""
    from datetime import datetime, timedelta
    
    start = datetime.strptime(start_date, "%Y-%m-%d")
    end = datetime.strptime(end_date, "%Y-%m-%d")
    
    payloads = []
    current = start
    while current <= end:
        payloads.append(current.strftime(date_format))
        current += timedelta(days=1)
    return payloads


def generate_uuid_payloads(count: int = 10) -> List[str]:
    """Generate UUID payloads."""
    import uuid
    return [str(uuid.uuid4()) for _ in range(count)]


def generate_pattern_payloads(pattern: str, count: int = 10) -> List[str]:
    """Generate payloads from a pattern.
    
    Pattern syntax:
    - [a-z]: lowercase letter
    - [A-Z]: uppercase letter
    - [0-9]: digit
    - [a-zA-Z]: any letter
    - [a-zA-Z0-9]: alphanumeric
    - {n}: repeat n times
    - Literal characters are kept as-is
    
    Example: "user[0-9]{4}" -> user0000, user0001, etc.
    """
    import random
    import string
    
    payloads = []
    
    # Simple implementation - generate random instances
    for _ in range(count):
        result = pattern
        
        # Handle character classes with repetition
        result = re.sub(r'\[a-z\]\{(\d+)\}', lambda m: ''.join(random.choices(string.ascii_lowercase, k=int(m.group(1)))), result)
        result = re.sub(r'\[A-Z\]\{(\d+)\}', lambda m: ''.join(random.choices(string.ascii_uppercase, k=int(m.group(1)))), result)
        result = re.sub(r'\[0-9\]\{(\d+)\}', lambda m: ''.join(random.choices(string.digits, k=int(m.group(1)))), result)
        result = re.sub(r'\[a-zA-Z\]\{(\d+)\}', lambda m: ''.join(random.choices(string.ascii_letters, k=int(m.group(1)))), result)
        result = re.sub(r'\[a-zA-Z0-9\]\{(\d+)\}', lambda m: ''.join(random.choices(string.ascii_letters + string.digits, k=int(m.group(1)))), result)
        
        # Handle single character classes
        result = re.sub(r'\[a-z\]', lambda m: random.choice(string.ascii_lowercase), result)
        result = re.sub(r'\[A-Z\]', lambda m: random.choice(string.ascii_uppercase), result)
        result = re.sub(r'\[0-9\]', lambda m: random.choice(string.digits), result)
        result = re.sub(r'\[a-zA-Z\]', lambda m: random.choice(string.ascii_letters), result)
        result = re.sub(r'\[a-zA-Z0-9\]', lambda m: random.choice(string.ascii_letters + string.digits), result)
        
        payloads.append(result)
    
    return payloads


def generate_from_config(config: GeneratorConfig) -> List[str]:
    """Generate payloads from a generator configuration."""
    gen_type = config.type.lower()
    params = config.params
    
    if gen_type == "number_range":
        return generate_number_range(
            params.get("start", 0),
            params.get("end", 100),
            params.get("step", 1),
            params.get("padding", 0)
        )
    elif gen_type == "char_range":
        return generate_char_range(
            params.get("start", "a"),
            params.get("end", "z")
        )
    elif gen_type == "date_range":
        return generate_date_range(
            params.get("start", "2024-01-01"),
            params.get("end", "2024-12-31"),
            params.get("format", "%Y-%m-%d")
        )
    elif gen_type == "uuid":
        return generate_uuid_payloads(params.get("count", 10))
    elif gen_type == "pattern":
        return generate_pattern_payloads(
            params.get("pattern", "[a-z]{8}"),
            params.get("count", 10)
        )
    elif gen_type == "custom_list":
        return params.get("values", [])
    
    return []


# ============================================================================
# GREP/EXTRACT RULES
# ============================================================================

@dataclass
class GrepRule:
    """A rule for matching content in responses."""
    name: str
    pattern: str
    is_regex: bool = True
    case_sensitive: bool = False
    extract_group: Optional[int] = None  # Regex group to extract
    
    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass 
class ExtractRule:
    """A rule for extracting data from responses."""
    name: str
    pattern: str
    start_marker: str = ""
    end_marker: str = ""
    regex_group: Optional[int] = None
    
    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class GrepMatch:
    """A match found by a grep rule."""
    rule_name: str
    matched_text: str
    position: int
    context: str  # Surrounding text
    extracted_value: Optional[str] = None
    
    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


def apply_grep_rules(content: str, rules: List[GrepRule]) -> List[GrepMatch]:
    """Apply grep rules to content and return matches."""
    matches = []
    
    for rule in rules:
        flags = 0 if rule.case_sensitive else re.IGNORECASE
        
        try:
            if rule.is_regex:
                for match in re.finditer(rule.pattern, content, flags):
                    # Get context (50 chars before and after)
                    start = max(0, match.start() - 50)
                    end = min(len(content), match.end() + 50)
                    context = content[start:end]
                    
                    extracted = None
                    if rule.extract_group is not None:
                        try:
                            extracted = match.group(rule.extract_group)
                        except IndexError:
                            pass
                    
                    matches.append(GrepMatch(
                        rule_name=rule.name,
                        matched_text=match.group(0),
                        position=match.start(),
                        context=context,
                        extracted_value=extracted or match.group(0)
                    ))
            else:
                # Simple string search
                search_content = content if rule.case_sensitive else content.lower()
                search_pattern = rule.pattern if rule.case_sensitive else rule.pattern.lower()
                
                idx = 0
                while True:
                    pos = search_content.find(search_pattern, idx)
                    if pos == -1:
                        break
                    
                    start = max(0, pos - 50)
                    end = min(len(content), pos + len(rule.pattern) + 50)
                    context = content[start:end]
                    
                    matches.append(GrepMatch(
                        rule_name=rule.name,
                        matched_text=content[pos:pos + len(rule.pattern)],
                        position=pos,
                        context=context,
                        extracted_value=content[pos:pos + len(rule.pattern)]
                    ))
                    idx = pos + 1
                    
        except re.error:
            # Invalid regex - skip
            pass
    
    return matches


def apply_extract_rules(content: str, rules: List[ExtractRule]) -> Dict[str, List[str]]:
    """Apply extract rules and return extracted data."""
    results = {}
    
    for rule in rules:
        extracted = []
        
        if rule.pattern:
            # Use regex pattern
            try:
                for match in re.finditer(rule.pattern, content, re.IGNORECASE):
                    if rule.regex_group is not None:
                        try:
                            extracted.append(match.group(rule.regex_group))
                        except IndexError:
                            extracted.append(match.group(0))
                    else:
                        extracted.append(match.group(0))
            except re.error:
                pass
        elif rule.start_marker and rule.end_marker:
            # Use start/end markers
            idx = 0
            while True:
                start = content.find(rule.start_marker, idx)
                if start == -1:
                    break
                start += len(rule.start_marker)
                end = content.find(rule.end_marker, start)
                if end == -1:
                    break
                extracted.append(content[start:end])
                idx = end + len(rule.end_marker)
        
        if extracted:
            results[rule.name] = extracted
    
    return results


# Pre-built extract rules for common data
COMMON_EXTRACT_RULES = [
    ExtractRule(name="emails", pattern=r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'),
    ExtractRule(name="urls", pattern=r'https?://[^\s<>"\']+'),
    ExtractRule(name="ip_addresses", pattern=r'\b(?:\d{1,3}\.){3}\d{1,3}\b'),
    ExtractRule(name="phone_numbers", pattern=r'[\+]?[(]?[0-9]{3}[)]?[-\s\.]?[0-9]{3}[-\s\.]?[0-9]{4,6}'),
    ExtractRule(name="jwt_tokens", pattern=r'eyJ[a-zA-Z0-9_-]*\.eyJ[a-zA-Z0-9_-]*\.[a-zA-Z0-9_-]*'),
    ExtractRule(name="api_keys", pattern=r'(?:api[_-]?key|apikey|api_secret)["\']?\s*[:=]\s*["\']?([a-zA-Z0-9_-]{20,})["\']?'),
    ExtractRule(name="aws_keys", pattern=r'(?:AKIA|ABIA|ACCA|ASIA)[A-Z0-9]{16}'),
    ExtractRule(name="private_keys", pattern=r'-----BEGIN (?:RSA |DSA |EC |OPENSSH )?PRIVATE KEY-----'),
    ExtractRule(name="hashes_md5", pattern=r'\b[a-fA-F0-9]{32}\b'),
    ExtractRule(name="hashes_sha1", pattern=r'\b[a-fA-F0-9]{40}\b'),
    ExtractRule(name="hashes_sha256", pattern=r'\b[a-fA-F0-9]{64}\b'),
    ExtractRule(name="credit_cards", pattern=r'\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|6(?:011|5[0-9]{2})[0-9]{12})\b'),
    ExtractRule(name="ssn", pattern=r'\b\d{3}-\d{2}-\d{4}\b'),
    ExtractRule(name="html_comments", pattern=r'<!--[\s\S]*?-->'),
    ExtractRule(name="hidden_inputs", pattern=r'<input[^>]*type=["\']?hidden["\']?[^>]*>', regex_group=0),
]


# ============================================================================
# RESPONSE CLUSTERING
# ============================================================================

@dataclass
class ResponseCluster:
    """A cluster of similar responses."""
    id: str
    response_ids: List[str]
    representative_hash: str
    avg_length: float
    status_code: int
    count: int
    similarity_threshold: float
    
    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


def compute_response_hash(body: str, status_code: int) -> str:
    """Compute a hash for response clustering."""
    # Normalize the body
    normalized = re.sub(r'\s+', ' ', body.strip())
    normalized = re.sub(r'\d+', 'N', normalized)  # Replace numbers
    
    content = f"{status_code}:{normalized}"
    return hashlib.md5(content.encode()).hexdigest()[:16]


def compute_similarity(text1: str, text2: str) -> float:
    """Compute similarity ratio between two texts."""
    return difflib.SequenceMatcher(None, text1, text2).ratio()


def cluster_responses(
    responses: List[Dict[str, Any]], 
    similarity_threshold: float = 0.85
) -> List[ResponseCluster]:
    """Cluster similar responses together."""
    clusters = []
    assigned = set()
    
    for i, resp1 in enumerate(responses):
        if resp1['id'] in assigned:
            continue
        
        cluster_ids = [resp1['id']]
        assigned.add(resp1['id'])
        
        hash1 = compute_response_hash(resp1.get('body', ''), resp1.get('status_code', 0))
        
        for j, resp2 in enumerate(responses):
            if i >= j or resp2['id'] in assigned:
                continue
            
            # Quick hash comparison first
            hash2 = compute_response_hash(resp2.get('body', ''), resp2.get('status_code', 0))
            
            if hash1 == hash2:
                cluster_ids.append(resp2['id'])
                assigned.add(resp2['id'])
            elif resp1.get('status_code') == resp2.get('status_code'):
                # Detailed similarity check
                similarity = compute_similarity(
                    resp1.get('body', ''),
                    resp2.get('body', '')
                )
                if similarity >= similarity_threshold:
                    cluster_ids.append(resp2['id'])
                    assigned.add(resp2['id'])
        
        # Create cluster
        cluster_responses_list = [r for r in responses if r['id'] in cluster_ids]
        avg_len = sum(r.get('response_length', 0) for r in cluster_responses_list) / len(cluster_responses_list)
        
        clusters.append(ResponseCluster(
            id=f"cluster-{len(clusters)}",
            response_ids=cluster_ids,
            representative_hash=hash1,
            avg_length=avg_len,
            status_code=resp1.get('status_code', 0),
            count=len(cluster_ids),
            similarity_threshold=similarity_threshold
        ))
    
    return clusters


def find_anomalous_responses(
    responses: List[Dict[str, Any]],
    clusters: List[ResponseCluster]
) -> List[str]:
    """Find responses that don't fit well into clusters (potential anomalies)."""
    # Responses in small clusters are more likely to be interesting
    anomalies = []
    
    if not clusters:
        return anomalies
    
    avg_cluster_size = sum(c.count for c in clusters) / len(clusters)
    
    for cluster in clusters:
        # Small clusters relative to average might be interesting
        if cluster.count < avg_cluster_size * 0.2:
            anomalies.extend(cluster.response_ids)
    
    return anomalies


# ============================================================================
# WAF/RATE LIMIT DETECTION
# ============================================================================

@dataclass
class WAFDetection:
    """Information about detected WAF/protection."""
    detected: bool
    waf_type: Optional[str] = None
    confidence: float = 0.0
    indicators: List[str] = field(default_factory=list)
    bypass_suggestions: List[str] = field(default_factory=list)
    
    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class RateLimitDetection:
    """Information about detected rate limiting."""
    detected: bool
    limit_type: Optional[str] = None  # "hard", "soft", "progressive"
    threshold: Optional[int] = None  # Estimated requests before limit
    retry_after: Optional[int] = None  # Seconds to wait
    indicators: List[str] = field(default_factory=list)
    
    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


# WAF signature patterns
WAF_SIGNATURES = {
    "cloudflare": {
        "headers": ["cf-ray", "cf-cache-status", "__cfduid", "cf-request-id"],
        "body_patterns": [r"cloudflare", r"cf-browser-verification", r"attention required"],
        "status_codes": [403, 503],
    },
    "akamai": {
        "headers": ["x-akamai-transformed", "akamai-origin-hop"],
        "body_patterns": [r"akamai", r"reference\s*#\s*[\d.]+"],
        "status_codes": [403],
    },
    "aws_waf": {
        "headers": ["x-amzn-requestid", "x-amz-cf-id"],
        "body_patterns": [r"request blocked", r"aws waf"],
        "status_codes": [403],
    },
    "imperva": {
        "headers": ["x-iinfo", "x-cdn"],
        "body_patterns": [r"incapsula", r"_incap_", r"imperva"],
        "status_codes": [403],
    },
    "sucuri": {
        "headers": ["x-sucuri-id", "x-sucuri-cache"],
        "body_patterns": [r"sucuri", r"cloudproxy"],
        "status_codes": [403],
    },
    "modsecurity": {
        "headers": ["mod_security", "modsecurity"],
        "body_patterns": [r"mod_security", r"modsec", r"NOYB"],
        "status_codes": [403, 406],
    },
    "f5_big_ip": {
        "headers": ["x-cnection", "x-wa-info"],
        "body_patterns": [r"f5", r"big-?ip", r"the requested url was rejected"],
        "status_codes": [403],
    },
    "barracuda": {
        "headers": ["barra_counter_session"],
        "body_patterns": [r"barracuda", r"barra_counter"],
        "status_codes": [403],
    },
    "fortinet": {
        "headers": [],
        "body_patterns": [r"fortigate", r"fortiweb", r"fortinet"],
        "status_codes": [403],
    },
    "generic_waf": {
        "headers": ["x-firewall", "x-security"],
        "body_patterns": [
            r"blocked", r"forbidden", r"security", r"attack detected",
            r"malicious", r"suspicious", r"threat"
        ],
        "status_codes": [403, 406, 429, 503],
    },
}


def detect_waf(headers: Dict[str, str], body: str, status_code: int) -> WAFDetection:
    """Detect if a WAF is present based on response characteristics."""
    detection = WAFDetection(detected=False)
    indicators = []
    
    headers_lower = {k.lower(): v for k, v in headers.items()}
    body_lower = body.lower()
    
    best_match = None
    best_score = 0
    
    for waf_name, signatures in WAF_SIGNATURES.items():
        score = 0
        waf_indicators = []
        
        # Check headers
        for header in signatures["headers"]:
            if header.lower() in headers_lower:
                score += 2
                waf_indicators.append(f"Header: {header}")
        
        # Check body patterns
        for pattern in signatures["body_patterns"]:
            if re.search(pattern, body_lower):
                score += 1
                waf_indicators.append(f"Body pattern: {pattern}")
        
        # Check status code
        if status_code in signatures["status_codes"]:
            score += 1
            waf_indicators.append(f"Status code: {status_code}")
        
        if score > best_score:
            best_score = score
            best_match = waf_name
            indicators = waf_indicators
    
    if best_score >= 2:
        detection.detected = True
        detection.waf_type = best_match
        detection.confidence = min(1.0, best_score / 5)
        detection.indicators = indicators
        
        # Add bypass suggestions
        detection.bypass_suggestions = get_waf_bypass_suggestions(best_match)
    
    return detection


def get_waf_bypass_suggestions(waf_type: str) -> List[str]:
    """Get bypass suggestions for a specific WAF."""
    common_bypasses = [
        "Try different encoding (URL, double URL, Unicode)",
        "Use case variations in payloads",
        "Add null bytes or newlines",
        "Use HTTP parameter pollution",
        "Try different HTTP methods",
        "Use payload fragmentation",
    ]
    
    specific_bypasses = {
        "cloudflare": [
            "Use Cloudflare-specific bypass payloads",
            "Try bypassing through origin IP",
            "Use HTTP/2 or WebSocket connections",
        ],
        "modsecurity": [
            "Check for paranoia level and adjust payloads",
            "Use comment injection in payloads",
            "Try SQL comment obfuscation (/*!50000*/)",
        ],
        "aws_waf": [
            "Check AWS WAF rule set being used",
            "Use encoding combinations",
        ],
    }
    
    return common_bypasses + specific_bypasses.get(waf_type, [])


def detect_rate_limiting(responses: List[Dict[str, Any]]) -> RateLimitDetection:
    """Detect rate limiting patterns in responses."""
    detection = RateLimitDetection(detected=False)
    indicators = []
    
    if not responses:
        return detection
    
    # Look for rate limit indicators
    rate_limit_codes = [429, 503, 509]
    blocked_count = sum(1 for r in responses if r.get('status_code') in rate_limit_codes)
    
    if blocked_count > 0:
        detection.detected = True
        indicators.append(f"{blocked_count} responses with rate limit status codes")
        
        # Try to find when rate limiting started
        for i, r in enumerate(responses):
            if r.get('status_code') in rate_limit_codes:
                detection.threshold = i
                detection.limit_type = "hard"
                break
        
        # Check for Retry-After header
        for r in responses:
            headers = r.get('headers', {})
            headers_lower = {k.lower(): v for k, v in headers.items()}
            if 'retry-after' in headers_lower:
                try:
                    detection.retry_after = int(headers_lower['retry-after'])
                    indicators.append(f"Retry-After header: {detection.retry_after}s")
                except ValueError:
                    pass
                break
    
    # Check for progressive slowdown (soft rate limiting)
    response_times = [r.get('response_time', 0) for r in responses]
    if len(response_times) > 10:
        first_half_avg = sum(response_times[:len(response_times)//2]) / (len(response_times)//2)
        second_half_avg = sum(response_times[len(response_times)//2:]) / (len(response_times)//2)
        
        if second_half_avg > first_half_avg * 2:
            detection.detected = True
            detection.limit_type = "progressive"
            indicators.append(f"Response time increased from {first_half_avg:.0f}ms to {second_half_avg:.0f}ms")
    
    detection.indicators = indicators
    return detection


# ============================================================================
# RECURSIVE PARAMETER DISCOVERY
# ============================================================================

@dataclass
class DiscoveredParameter:
    """A discovered parameter from response analysis."""
    name: str
    source: str  # "html_form", "javascript", "url", "json", "comment"
    param_type: str  # "query", "post", "header", "cookie"
    sample_value: Optional[str] = None
    
    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


def discover_parameters(html_content: str, url: str = "") -> List[DiscoveredParameter]:
    """Discover parameters from HTML content and URL."""
    params = []
    seen = set()
    
    # Extract from URL query string
    if '?' in url:
        query_string = url.split('?', 1)[1]
        for param in query_string.split('&'):
            if '=' in param:
                name = param.split('=')[0]
                value = param.split('=')[1] if '=' in param else None
                if name and name not in seen:
                    params.append(DiscoveredParameter(
                        name=name,
                        source="url",
                        param_type="query",
                        sample_value=value
                    ))
                    seen.add(name)
    
    # Extract from HTML forms
    form_patterns = [
        r'<input[^>]*name=["\']([^"\']+)["\'][^>]*>',
        r'<select[^>]*name=["\']([^"\']+)["\'][^>]*>',
        r'<textarea[^>]*name=["\']([^"\']+)["\'][^>]*>',
    ]
    for pattern in form_patterns:
        for match in re.finditer(pattern, html_content, re.IGNORECASE):
            name = match.group(1)
            if name and name not in seen:
                params.append(DiscoveredParameter(
                    name=name,
                    source="html_form",
                    param_type="post",
                    sample_value=None
                ))
                seen.add(name)
    
    # Extract from JavaScript
    js_patterns = [
        r'["\'](\w+)["\']\s*:\s*["\'][^"\']*["\']',  # JSON-like
        r'\.(\w+)\s*=',  # Assignment
        r'data\[["\']([\w_]+)["\']\]',  # Array access
        r'(?:get|post|put|delete)\s*\([^)]*["\'](\w+)["\']',  # API calls
    ]
    for pattern in js_patterns:
        for match in re.finditer(pattern, html_content):
            name = match.group(1)
            if name and name not in seen and len(name) > 1:
                params.append(DiscoveredParameter(
                    name=name,
                    source="javascript",
                    param_type="query",
                    sample_value=None
                ))
                seen.add(name)
    
    # Extract from HTML comments
    comment_pattern = r'<!--[\s\S]*?-->'
    for match in re.finditer(comment_pattern, html_content):
        comment = match.group(0)
        # Look for parameter-like patterns in comments
        param_pattern = r'(?:param|parameter|field|input|name)\s*[=:]\s*["\']?(\w+)["\']?'
        for param_match in re.finditer(param_pattern, comment, re.IGNORECASE):
            name = param_match.group(1)
            if name and name not in seen:
                params.append(DiscoveredParameter(
                    name=name,
                    source="comment",
                    param_type="query",
                    sample_value=None
                ))
                seen.add(name)
    
    return params


def discover_endpoints(html_content: str, base_url: str = "") -> List[str]:
    """Discover endpoints from HTML content."""
    endpoints = set()
    
    # Extract href and src attributes
    url_patterns = [
        r'href=["\']([^"\']+)["\']',
        r'src=["\']([^"\']+)["\']',
        r'action=["\']([^"\']+)["\']',
        r'data-url=["\']([^"\']+)["\']',
    ]
    
    for pattern in url_patterns:
        for match in re.finditer(pattern, html_content, re.IGNORECASE):
            url = match.group(1)
            # Filter out non-http URLs and external domains
            if url.startswith(('http://', 'https://', '/')):
                if url.startswith('/'):
                    # Make absolute if we have base URL
                    if base_url:
                        from urllib.parse import urljoin
                        url = urljoin(base_url, url)
                endpoints.add(url)
            elif not url.startswith(('#', 'javascript:', 'mailto:', 'tel:')):
                endpoints.add(url)
    
    # Extract from JavaScript API calls
    api_patterns = [
        r'fetch\s*\(\s*["\']([^"\']+)["\']',
        r'\.(?:get|post|put|delete|patch)\s*\(\s*["\']([^"\']+)["\']',
        r'url\s*:\s*["\']([^"\']+)["\']',
        r'endpoint\s*:\s*["\']([^"\']+)["\']',
    ]
    
    for pattern in api_patterns:
        for match in re.finditer(pattern, html_content):
            endpoint = match.group(1)
            if not endpoint.startswith(('http://', 'https://', '/')):
                endpoint = '/' + endpoint
            endpoints.add(endpoint)
    
    return list(endpoints)


# ============================================================================
# PAYLOAD MUTATION
# ============================================================================

def mutate_payload(payload: str, mutation_type: str) -> List[str]:
    """Generate mutations of a payload."""
    mutations = [payload]  # Include original
    
    if mutation_type == "case":
        mutations.extend([
            payload.lower(),
            payload.upper(),
            payload.swapcase(),
            payload.capitalize(),
            ''.join(c.upper() if i % 2 else c.lower() for i, c in enumerate(payload)),
        ])
    
    elif mutation_type == "encoding":
        mutations.extend([
            encode_payload(payload, EncodingType.URL),
            encode_payload(payload, EncodingType.DOUBLE_URL),
            encode_payload(payload, EncodingType.HTML_ENTITIES),
            encode_payload(payload, EncodingType.UNICODE),
        ])
    
    elif mutation_type == "whitespace":
        mutations.extend([
            payload.replace(' ', '\t'),
            payload.replace(' ', '\n'),
            payload.replace(' ', '\r\n'),
            payload.replace(' ', '  '),
            payload.replace(' ', '/**/'),  # SQL comment
            ' ' + payload,
            payload + ' ',
            '\n' + payload,
            payload + '\n',
        ])
    
    elif mutation_type == "null_byte":
        mutations.extend([
            payload + '\x00',
            '\x00' + payload,
            payload.replace(' ', '\x00'),
            payload + '%00',
            '%00' + payload,
        ])
    
    elif mutation_type == "comment":
        # Add various comment styles
        mutations.extend([
            payload.replace(' ', '/**/'),  # SQL
            payload.replace(' ', '//\n'),  # Line comment
            f'<!--{payload}-->',  # HTML
            f'/*{payload}*/',
        ])
    
    elif mutation_type == "concatenation":
        # String concatenation bypasses
        if "'" in payload:
            mutations.append(payload.replace("'", "'+'")),
            mutations.append(payload.replace("'", "'||'")),
        if '"' in payload:
            mutations.append(payload.replace('"', '"+"')),
    
    return list(set(mutations))


def generate_all_mutations(payload: str) -> List[str]:
    """Generate all mutation variants of a payload."""
    mutations = set([payload])
    
    for mutation_type in ["case", "encoding", "whitespace", "null_byte"]:
        for mutated in mutate_payload(payload, mutation_type):
            mutations.add(mutated)
    
    return list(mutations)


# ============================================================================
# SMART PAYLOAD SELECTION
# ============================================================================

def prioritize_payloads(
    payloads: List[str],
    target_info: Dict[str, Any]
) -> List[str]:
    """Prioritize payloads based on target information."""
    # Extract target characteristics
    content_type = target_info.get('content_type', '')
    technology = target_info.get('technology', [])
    
    priority_map = defaultdict(int)
    
    for payload in payloads:
        score = 0
        payload_lower = payload.lower()
        
        # Prioritize based on content type
        if 'json' in content_type:
            if '"' in payload or '{' in payload:
                score += 2
        elif 'xml' in content_type:
            if '<' in payload or '>' in payload:
                score += 2
        
        # Prioritize based on detected technology
        for tech in technology:
            tech_lower = tech.lower()
            if 'php' in tech_lower and ('<?php' in payload_lower or 'php:' in payload_lower):
                score += 3
            elif 'asp' in tech_lower and ('<%' in payload_lower or 'asp' in payload_lower):
                score += 3
            elif 'java' in tech_lower and ('${' in payload_lower or 'java' in payload_lower):
                score += 3
            elif 'python' in tech_lower and ('{{' in payload_lower or '__' in payload_lower):
                score += 3
            elif 'node' in tech_lower and ('require(' in payload_lower or 'process' in payload_lower):
                score += 3
        
        # General payload characteristics
        if any(c in payload for c in ['\'', '"', '<', '>']):
            score += 1
        
        priority_map[payload] = score
    
    # Sort by priority (descending)
    return sorted(payloads, key=lambda p: priority_map[p], reverse=True)


# ============================================================================
# EXPORT FUNCTIONS
# ============================================================================

def export_advanced_analysis(
    responses: List[Dict[str, Any]],
    clusters: List[ResponseCluster],
    waf_detection: WAFDetection,
    rate_limit: RateLimitDetection,
    discovered_params: List[DiscoveredParameter],
    extracted_data: Dict[str, List[str]]
) -> Dict[str, Any]:
    """Export advanced analysis results."""
    return {
        "clustering": {
            "total_clusters": len(clusters),
            "clusters": [c.to_dict() for c in clusters],
        },
        "waf_detection": waf_detection.to_dict(),
        "rate_limiting": rate_limit.to_dict(),
        "discovered_parameters": [p.to_dict() for p in discovered_params],
        "extracted_data": extracted_data,
        "statistics": {
            "total_responses": len(responses),
            "unique_status_codes": len(set(r.get('status_code') for r in responses)),
            "avg_response_time": sum(r.get('response_time', 0) for r in responses) / len(responses) if responses else 0,
        }
    }


# ============================================================================
# OFFENSIVE SECURITY ANALYSIS
# For analyzing sandboxed software, malware behavior, and C2 communication
# ============================================================================

@dataclass
class C2Indicator:
    """C2 (Command & Control) communication indicator."""
    indicator_type: str  # "domain", "ip", "url", "protocol", "beacon"
    value: str
    confidence: float  # 0-1
    framework: Optional[str] = None  # "cobalt_strike", "metasploit", "empire", etc.
    evidence: List[str] = field(default_factory=list)
    
    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class MalwareBehavior:
    """Detected malware behavior pattern."""
    behavior_type: str  # "persistence", "evasion", "exfiltration", "lateral_movement"
    technique: str
    mitre_id: Optional[str] = None  # MITRE ATT&CK ID
    severity: str = "medium"
    indicators: List[str] = field(default_factory=list)
    recommendation: str = ""
    
    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class SandboxEvasion:
    """Detected sandbox evasion technique."""
    technique: str
    detection_method: str
    indicators: List[str] = field(default_factory=list)
    bypass_type: str = ""  # "timing", "environment", "behavior"
    
    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class OffensiveAnalysisResult:
    """Complete offensive analysis result."""
    c2_indicators: List[C2Indicator] = field(default_factory=list)
    malware_behaviors: List[MalwareBehavior] = field(default_factory=list)
    sandbox_evasions: List[SandboxEvasion] = field(default_factory=list)
    exploit_indicators: List[Dict[str, Any]] = field(default_factory=list)
    risk_score: float = 0.0
    threat_level: str = "low"  # "critical", "high", "medium", "low", "info"
    iocs: Dict[str, List[str]] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "c2_indicators": [c.to_dict() for c in self.c2_indicators],
            "malware_behaviors": [m.to_dict() for m in self.malware_behaviors],
            "sandbox_evasions": [s.to_dict() for s in self.sandbox_evasions],
            "exploit_indicators": self.exploit_indicators,
            "risk_score": self.risk_score,
            "threat_level": self.threat_level,
            "iocs": self.iocs,
        }


# C2 Framework Signatures
C2_FRAMEWORK_SIGNATURES = {
    "cobalt_strike": {
        "patterns": [
            r"beacon\s*payload",
            r"malleable\s*c2",
            r"watermark\s*=\s*\d+",
            r"spawn\s*to",
            r"process[-_]inject",
            r"jump\s*psexec",
            r"hashdump",
            r"logonpasswords",
            r"dcsync",
            r"golden\s*ticket",
        ],
        "user_agents": [
            "Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.0;",
            "Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 5.1;",
        ],
        "default_ports": [443, 80, 8080, 8443],
    },
    "metasploit": {
        "patterns": [
            r"meterpreter",
            r"reverse_tcp",
            r"reverse_http",
            r"bind_tcp",
            r"multi/handler",
            r"exploit/multi",
            r"post/windows",
            r"post/linux",
            r"auxiliary/scanner",
            r"payload/windows",
        ],
        "default_ports": [4444, 4445, 5555],
    },
    "empire": {
        "patterns": [
            r"empire\s*agent",
            r"stager",
            r"invoke-empire",
            r"powershell\s*empire",
            r"launcher\.bat",
        ],
        "default_ports": [443, 80],
    },
    "sliver": {
        "patterns": [
            r"sliver\s*implant",
            r"mtls\s*listener",
            r"wg\s*listener",
            r"dns\s*canary",
        ],
        "default_ports": [443, 8888, 31337],
    },
    "brute_ratel": {
        "patterns": [
            r"brc4",
            r"brute\s*ratel",
            r"badger",
        ],
        "default_ports": [443],
    },
    "covenant": {
        "patterns": [
            r"covenant",
            r"grunt\s*stager",
            r"grunt\s*payload",
        ],
        "default_ports": [80, 443],
    },
}

# MITRE ATT&CK Mappings for Malware Behaviors
MITRE_MAPPINGS = {
    # Persistence
    "registry_run_key": {"id": "T1547.001", "tactic": "Persistence", "technique": "Boot or Logon Autostart Execution: Registry Run Keys"},
    "scheduled_task": {"id": "T1053.005", "tactic": "Persistence", "technique": "Scheduled Task/Job: Scheduled Task"},
    "startup_folder": {"id": "T1547.001", "tactic": "Persistence", "technique": "Boot or Logon Autostart Execution: Registry Run Keys"},
    "service_creation": {"id": "T1543.003", "tactic": "Persistence", "technique": "Create or Modify System Process: Windows Service"},
    
    # Defense Evasion
    "process_injection": {"id": "T1055", "tactic": "Defense Evasion", "technique": "Process Injection"},
    "dll_injection": {"id": "T1055.001", "tactic": "Defense Evasion", "technique": "Process Injection: DLL Injection"},
    "process_hollowing": {"id": "T1055.012", "tactic": "Defense Evasion", "technique": "Process Injection: Process Hollowing"},
    "amsi_bypass": {"id": "T1562.001", "tactic": "Defense Evasion", "technique": "Impair Defenses: Disable or Modify Tools"},
    "etw_bypass": {"id": "T1562.006", "tactic": "Defense Evasion", "technique": "Impair Defenses: Indicator Blocking"},
    "timestomp": {"id": "T1070.006", "tactic": "Defense Evasion", "technique": "Indicator Removal: Timestomp"},
    
    # Credential Access
    "credential_dumping": {"id": "T1003", "tactic": "Credential Access", "technique": "OS Credential Dumping"},
    "lsass_dump": {"id": "T1003.001", "tactic": "Credential Access", "technique": "OS Credential Dumping: LSASS Memory"},
    "sam_dump": {"id": "T1003.002", "tactic": "Credential Access", "technique": "OS Credential Dumping: SAM"},
    "keylogging": {"id": "T1056.001", "tactic": "Credential Access", "technique": "Input Capture: Keylogging"},
    
    # Discovery
    "system_info": {"id": "T1082", "tactic": "Discovery", "technique": "System Information Discovery"},
    "process_discovery": {"id": "T1057", "tactic": "Discovery", "technique": "Process Discovery"},
    "network_discovery": {"id": "T1046", "tactic": "Discovery", "technique": "Network Service Scanning"},
    
    # Lateral Movement
    "psexec": {"id": "T1570", "tactic": "Lateral Movement", "technique": "Lateral Tool Transfer"},
    "wmi_execution": {"id": "T1047", "tactic": "Execution", "technique": "Windows Management Instrumentation"},
    "smb_exec": {"id": "T1021.002", "tactic": "Lateral Movement", "technique": "Remote Services: SMB/Windows Admin Shares"},
    
    # Exfiltration
    "dns_exfil": {"id": "T1048.003", "tactic": "Exfiltration", "technique": "Exfiltration Over Alternative Protocol: DNS"},
    "http_exfil": {"id": "T1048.002", "tactic": "Exfiltration", "technique": "Exfiltration Over Alternative Protocol: HTTP"},
    "cloud_exfil": {"id": "T1567", "tactic": "Exfiltration", "technique": "Exfiltration Over Web Service"},
    
    # Command and Control
    "dns_c2": {"id": "T1071.004", "tactic": "Command and Control", "technique": "Application Layer Protocol: DNS"},
    "http_c2": {"id": "T1071.001", "tactic": "Command and Control", "technique": "Application Layer Protocol: HTTP"},
    "encrypted_channel": {"id": "T1573", "tactic": "Command and Control", "technique": "Encrypted Channel"},
}


def analyze_c2_indicators(content: str, headers: Dict[str, str] = None) -> List[C2Indicator]:
    """Analyze content for C2 communication indicators."""
    indicators = []
    
    if headers is None:
        headers = {}
    
    # Check for C2 framework signatures
    for framework, sigs in C2_FRAMEWORK_SIGNATURES.items():
        for pattern in sigs["patterns"]:
            if re.search(pattern, content, re.IGNORECASE):
                indicators.append(C2Indicator(
                    indicator_type="framework",
                    value=framework,
                    confidence=0.8,
                    framework=framework,
                    evidence=[f"Pattern match: {pattern}"]
                ))
                break
    
    # Extract potential C2 domains
    domain_patterns = [
        r"(?:https?://)?([a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.(?:[a-zA-Z]{2,}))",
        r"\.duckdns\.org",
        r"\.no-ip\.(?:org|biz)",
        r"\.ddns\.net",
        r"\.hopto\.org",
        r"ngrok\.io",
        r"cloudflare.*tunnel",
    ]
    
    for pattern in domain_patterns:
        for match in re.finditer(pattern, content, re.IGNORECASE):
            domain = match.group(0)
            # Skip common legitimate domains
            if not any(legit in domain.lower() for legit in ['google', 'microsoft', 'amazon', 'github']):
                indicators.append(C2Indicator(
                    indicator_type="domain",
                    value=domain,
                    confidence=0.5,
                    evidence=[f"Suspicious domain pattern: {domain}"]
                ))
    
    # Extract IP addresses with ports (potential C2)
    ip_port_pattern = r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}):(\d{1,5})"
    for match in re.finditer(ip_port_pattern, content):
        ip, port = match.groups()
        port_int = int(port)
        
        # High-value C2 ports
        suspicious_ports = [4444, 4445, 5555, 8080, 8443, 31337, 1234, 9999]
        confidence = 0.7 if port_int in suspicious_ports else 0.4
        
        indicators.append(C2Indicator(
            indicator_type="ip",
            value=f"{ip}:{port}",
            confidence=confidence,
            evidence=[f"IP:Port combination detected"]
        ))
    
    # Check for beacon patterns
    beacon_patterns = [
        (r"sleep\s*[=:]\s*(\d+)", "beacon_sleep"),
        (r"jitter\s*[=:]\s*(\d+)", "beacon_jitter"),
        (r"callback\s*[=:]", "callback_config"),
        (r"heartbeat", "heartbeat"),
        (r"checkin", "checkin"),
    ]
    
    for pattern, indicator_name in beacon_patterns:
        if re.search(pattern, content, re.IGNORECASE):
            indicators.append(C2Indicator(
                indicator_type="beacon",
                value=indicator_name,
                confidence=0.6,
                evidence=[f"Beacon pattern: {pattern}"]
            ))
    
    return indicators


def analyze_malware_behaviors(content: str) -> List[MalwareBehavior]:
    """Analyze content for malware behavior patterns."""
    behaviors = []
    
    # Persistence behaviors
    persistence_patterns = [
        (r"HKLM\\.*\\Run|HKCU\\.*\\Run|CurrentVersion\\Run", "registry_run_key", "Registry Run Key Persistence"),
        (r"schtasks\s*/create|New-ScheduledTask", "scheduled_task", "Scheduled Task Creation"),
        (r"startup\s*folder|shell:startup", "startup_folder", "Startup Folder Persistence"),
        (r"sc\s*create|New-Service", "service_creation", "Service Creation"),
        (r"wmic\s*startup|Win32_StartupCommand", "wmi_persistence", "WMI Persistence"),
    ]
    
    for pattern, technique_key, description in persistence_patterns:
        if re.search(pattern, content, re.IGNORECASE):
            mitre = MITRE_MAPPINGS.get(technique_key, {})
            behaviors.append(MalwareBehavior(
                behavior_type="persistence",
                technique=description,
                mitre_id=mitre.get("id"),
                severity="high",
                indicators=[pattern],
                recommendation=f"Monitor for {description.lower()} - MITRE: {mitre.get('id', 'N/A')}"
            ))
    
    # Defense evasion behaviors
    evasion_patterns = [
        (r"CreateRemoteThread|NtCreateThreadEx|WriteProcessMemory", "process_injection", "Process Injection"),
        (r"LoadLibrary.*inject|reflective\s*dll|manual\s*map", "dll_injection", "DLL Injection"),
        (r"NtUnmapViewOfSection|hollow|doppelgang", "process_hollowing", "Process Hollowing"),
        (r"amsi.*bypass|AmsiScanBuffer.*patch", "amsi_bypass", "AMSI Bypass"),
        (r"etw.*bypass|EtwEventWrite.*patch", "etw_bypass", "ETW Bypass"),
        (r"timestomp|SetFileTime|touch.*\-d", "timestomp", "Timestomping"),
    ]
    
    for pattern, technique_key, description in evasion_patterns:
        if re.search(pattern, content, re.IGNORECASE):
            mitre = MITRE_MAPPINGS.get(technique_key, {})
            behaviors.append(MalwareBehavior(
                behavior_type="evasion",
                technique=description,
                mitre_id=mitre.get("id"),
                severity="high",
                indicators=[pattern],
                recommendation=f"Defense evasion technique: {description}"
            ))
    
    # Credential access behaviors
    cred_patterns = [
        (r"mimikatz|sekurlsa|logonpasswords|wdigest", "credential_dumping", "Credential Dumping"),
        (r"lsass.*dump|procdump.*lsass|comsvcs.*MiniDump", "lsass_dump", "LSASS Memory Dump"),
        (r"reg\s*save.*sam|reg\s*save.*system|secretsdump", "sam_dump", "SAM Database Dump"),
        (r"keylog|GetAsyncKeyState|SetWindowsHookEx.*WH_KEYBOARD", "keylogging", "Keylogging"),
    ]
    
    for pattern, technique_key, description in cred_patterns:
        if re.search(pattern, content, re.IGNORECASE):
            mitre = MITRE_MAPPINGS.get(technique_key, {})
            behaviors.append(MalwareBehavior(
                behavior_type="credential_access",
                technique=description,
                mitre_id=mitre.get("id"),
                severity="critical",
                indicators=[pattern],
                recommendation=f"Credential theft technique detected: {description}"
            ))
    
    # Exfiltration behaviors
    exfil_patterns = [
        (r"dns\s*tunnel|dns.*exfil|subdomain.*encode", "dns_exfil", "DNS Exfiltration"),
        (r"http.*post.*data|upload.*file|send.*loot", "http_exfil", "HTTP Exfiltration"),
        (r"telegram.*bot|discord.*webhook|slack.*webhook", "cloud_exfil", "Cloud Service Exfiltration"),
    ]
    
    for pattern, technique_key, description in exfil_patterns:
        if re.search(pattern, content, re.IGNORECASE):
            mitre = MITRE_MAPPINGS.get(technique_key, {})
            behaviors.append(MalwareBehavior(
                behavior_type="exfiltration",
                technique=description,
                mitre_id=mitre.get("id"),
                severity="high",
                indicators=[pattern],
                recommendation=f"Data exfiltration channel: {description}"
            ))
    
    return behaviors


def analyze_sandbox_evasion(content: str) -> List[SandboxEvasion]:
    """Analyze content for sandbox evasion techniques."""
    evasions = []
    
    # VM/Sandbox detection patterns
    vm_patterns = [
        (r"vmware|virtualbox|vbox|qemu|hyperv|xen", "environment", "VM Detection"),
        (r"sandbox|cuckoo|any\.run|hybrid-analysis|virustotal", "environment", "Sandbox Detection"),
        (r"wine\s*detect|wine_get_version", "environment", "Wine Detection"),
        (r"IsDebuggerPresent|CheckRemoteDebugger|NtQueryInformationProcess", "debugger", "Debugger Detection"),
        (r"rdtsc|GetTickCount.*diff|QueryPerformanceCounter", "timing", "Timing-based Detection"),
    ]
    
    for pattern, bypass_type, technique in vm_patterns:
        if re.search(pattern, content, re.IGNORECASE):
            evasions.append(SandboxEvasion(
                technique=technique,
                detection_method=pattern,
                indicators=[pattern],
                bypass_type=bypass_type
            ))
    
    # Anti-analysis patterns
    anti_analysis = [
        (r"anti[_-]?debug|anti[_-]?vm|anti[_-]?analysis", "behavioral", "Anti-Analysis Framework"),
        (r"sleep\s*\(\s*\d{5,}\s*\)", "timing", "Long Sleep (Sleep Evasion)"),
        (r"GetCursorPos.*loop|mouse.*move.*detect", "behavioral", "Human Interaction Check"),
        (r"GetSystemMetrics|screen.*resolution.*check", "environment", "Screen Resolution Check"),
        (r"mac.*address.*check|adapter.*count", "environment", "MAC Address/NIC Check"),
        (r"cpu.*count|processor.*count|core.*count", "environment", "CPU Count Check"),
        (r"memory.*size|GlobalMemoryStatus", "environment", "Memory Size Check"),
        (r"disk.*size|GetDiskFreeSpace", "environment", "Disk Size Check"),
        (r"username.*check|computername.*check", "environment", "Username/Computer Name Check"),
    ]
    
    for pattern, bypass_type, technique in anti_analysis:
        if re.search(pattern, content, re.IGNORECASE):
            evasions.append(SandboxEvasion(
                technique=technique,
                detection_method=pattern,
                indicators=[pattern],
                bypass_type=bypass_type
            ))
    
    return evasions


def extract_iocs(content: str) -> Dict[str, List[str]]:
    """Extract Indicators of Compromise from content."""
    iocs = {
        "ips": [],
        "domains": [],
        "urls": [],
        "hashes_md5": [],
        "hashes_sha1": [],
        "hashes_sha256": [],
        "emails": [],
        "bitcoin_addresses": [],
        "monero_addresses": [],
        "file_paths": [],
        "registry_keys": [],
        "mutexes": [],
    }
    
    # IP addresses
    ip_pattern = r"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b"
    iocs["ips"] = list(set(re.findall(ip_pattern, content)))
    
    # Domains
    domain_pattern = r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b"
    potential_domains = set(re.findall(domain_pattern, content))
    # Filter out common domains
    common_domains = {'google.com', 'microsoft.com', 'github.com', 'amazon.com', 'example.com'}
    iocs["domains"] = [d for d in potential_domains if d.lower() not in common_domains]
    
    # URLs
    url_pattern = r"https?://[^\s<>\"\'{}|\\^`\[\]]+"
    iocs["urls"] = list(set(re.findall(url_pattern, content)))
    
    # Hashes
    iocs["hashes_md5"] = list(set(re.findall(r"\b[a-fA-F0-9]{32}\b", content)))
    iocs["hashes_sha1"] = list(set(re.findall(r"\b[a-fA-F0-9]{40}\b", content)))
    iocs["hashes_sha256"] = list(set(re.findall(r"\b[a-fA-F0-9]{64}\b", content)))
    
    # Emails
    email_pattern = r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}"
    iocs["emails"] = list(set(re.findall(email_pattern, content)))
    
    # Cryptocurrency addresses
    iocs["bitcoin_addresses"] = list(set(re.findall(r"\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b", content)))
    iocs["monero_addresses"] = list(set(re.findall(r"\b4[0-9AB][0-9a-zA-Z]{93}\b", content)))
    
    # File paths (Windows and Unix)
    windows_path = r"[A-Za-z]:\\(?:[^\\/:*?\"<>|\r\n]+\\)*[^\\/:*?\"<>|\r\n]*"
    unix_path = r"/(?:[^/\0]+/)*[^/\0]+"
    iocs["file_paths"] = list(set(re.findall(windows_path, content) + re.findall(unix_path, content)))[:50]
    
    # Registry keys
    reg_pattern = r"(?:HKLM|HKCU|HKCR|HKU|HKCC)\\[^\s\"']+"
    iocs["registry_keys"] = list(set(re.findall(reg_pattern, content, re.IGNORECASE)))
    
    # Mutexes
    mutex_pattern = r"(?:Global\\|Local\\)?[A-Za-z0-9_-]{8,}"
    # Filter to likely mutex patterns
    potential_mutexes = re.findall(mutex_pattern, content)
    iocs["mutexes"] = [m for m in set(potential_mutexes) if len(m) >= 10][:20]
    
    # Remove empty lists
    return {k: v for k, v in iocs.items() if v}


def perform_offensive_analysis(
    responses: List[Dict[str, Any]],
    include_c2: bool = True,
    include_malware: bool = True,
    include_evasion: bool = True,
    include_iocs: bool = True
) -> OffensiveAnalysisResult:
    """Perform comprehensive offensive security analysis on fuzzing responses."""
    result = OffensiveAnalysisResult()
    
    all_content = ""
    all_headers = {}
    
    for resp in responses:
        body = resp.get('body', '')
        headers = resp.get('headers', {})
        
        all_content += body + "\n"
        all_headers.update(headers)
    
    # C2 Analysis
    if include_c2:
        result.c2_indicators = analyze_c2_indicators(all_content, all_headers)
    
    # Malware Behavior Analysis
    if include_malware:
        result.malware_behaviors = analyze_malware_behaviors(all_content)
    
    # Sandbox Evasion Analysis
    if include_evasion:
        result.sandbox_evasions = analyze_sandbox_evasion(all_content)
    
    # IOC Extraction
    if include_iocs:
        result.iocs = extract_iocs(all_content)
    
    # Calculate risk score
    score = 0
    
    # C2 indicators add significant risk
    score += len(result.c2_indicators) * 15
    
    # Critical malware behaviors
    critical_behaviors = [b for b in result.malware_behaviors if b.severity == "critical"]
    high_behaviors = [b for b in result.malware_behaviors if b.severity == "high"]
    score += len(critical_behaviors) * 20
    score += len(high_behaviors) * 10
    
    # Sandbox evasion
    score += len(result.sandbox_evasions) * 5
    
    # IOCs
    if result.iocs:
        score += len(result.iocs.get("bitcoin_addresses", [])) * 10
        score += len(result.iocs.get("monero_addresses", [])) * 10
    
    result.risk_score = min(100, score)
    
    # Determine threat level
    if result.risk_score >= 80:
        result.threat_level = "critical"
    elif result.risk_score >= 60:
        result.threat_level = "high"
    elif result.risk_score >= 40:
        result.threat_level = "medium"
    elif result.risk_score >= 20:
        result.threat_level = "low"
    else:
        result.threat_level = "info"
    
    return result


# ============================================================================
# OFFENSIVE PAYLOAD GENERATORS
# Specialized payloads for analyzing sandboxed software
# ============================================================================

def generate_c2_probe_payloads() -> List[str]:
    """Generate payloads for probing C2 infrastructure."""
    payloads = [
        # Beacon probe patterns
        "beacon",
        "callback",
        "heartbeat",
        "checkin",
        "task",
        "command",
        "exfil",
        
        # Framework-specific probes
        "meterpreter",
        "stager",
        "empire",
        "sliver",
        "covenant",
        
        # Protocol probes
        "dns://",
        "icmp://",
        "http://c2.",
        "https://beacon.",
        "wss://cmd.",
        
        # Configuration probes
        "config.json",
        "beacon.config",
        "c2.config",
        "payload.bin",
        "stager.ps1",
        "loader.dll",
    ]
    return payloads


def generate_evasion_test_payloads() -> List[str]:
    """Generate payloads for testing sandbox evasion."""
    payloads = [
        # VM detection strings
        "VMware",
        "VirtualBox",
        "QEMU",
        "Hyper-V",
        "Xen",
        "KVM",
        
        # Sandbox detection
        "sandbox",
        "cuckoo",
        "any.run",
        "hybrid-analysis",
        
        # Anti-debug
        "IsDebuggerPresent",
        "CheckRemoteDebuggerPresent",
        "NtQueryInformationProcess",
        "debug_mode",
        
        # Timing checks
        "sleep(60000)",
        "GetTickCount",
        "rdtsc",
        
        # Environment checks
        "GetSystemMetrics",
        "GetCursorPos",
        "mouse_move",
    ]
    return payloads


def generate_malware_string_payloads() -> List[str]:
    """Generate common malware string payloads for detection testing."""
    payloads = [
        # Persistence
        "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
        "schtasks /create",
        "sc create",
        "New-Service",
        "startup folder",
        
        # Process injection
        "CreateRemoteThread",
        "WriteProcessMemory",
        "VirtualAllocEx",
        "NtMapViewOfSection",
        "QueueUserAPC",
        
        # Credential theft
        "mimikatz",
        "sekurlsa::logonpasswords",
        "lsass.dmp",
        "hashdump",
        "SAM database",
        
        # Evasion
        "amsi.dll",
        "AmsiScanBuffer",
        "etw bypass",
        "unhook ntdll",
        
        # Exfiltration
        "ftp upload",
        "http post",
        "dns exfil",
        "telegram bot",
    ]
    return payloads


def generate_api_hooking_payloads() -> List[str]:
    """Generate API hooking detection payloads."""
    payloads = [
        # Windows API hooks
        "ntdll.dll",
        "kernel32.dll",
        "kernelbase.dll",
        "NtCreateFile",
        "NtWriteFile",
        "NtReadFile",
        "NtCreateProcess",
        "NtCreateThread",
        "ZwMapViewOfSection",
        
        # Syscall
        "syscall",
        "sysenter",
        "int 2e",
        
        # Hook detection
        "hook detected",
        "inline hook",
        "iat hook",
        "eat hook",
        "trampoline",
        
        # Bypass techniques
        "direct syscall",
        "unhook",
        "fresh copy",
        "heaven's gate",
    ]
    return payloads


# ============================================================================
# EDR/AV SIGNATURE PATTERNS
# ============================================================================

EDR_SIGNATURES = {
    "crowdstrike": {
        "patterns": [r"csagent", r"falcon", r"csfalcon"],
        "processes": ["csfalconservice.exe", "csagent.exe"],
    },
    "carbon_black": {
        "patterns": [r"carbonblack", r"cb\.exe", r"cbdefense"],
        "processes": ["cb.exe", "cbcomms.exe"],
    },
    "sentinel_one": {
        "patterns": [r"sentinelone", r"sentinel", r"s1agent"],
        "processes": ["sentinelagent.exe", "sentinelctl.exe"],
    },
    "defender": {
        "patterns": [r"microsoft defender", r"msmpeng", r"mpcmdrun"],
        "processes": ["msmpeng.exe", "mpcmdrun.exe"],
    },
    "symantec": {
        "patterns": [r"symantec", r"norton", r"sep14"],
        "processes": ["ccsvchst.exe", "rtvscan.exe"],
    },
    "mcafee": {
        "patterns": [r"mcafee", r"mfeann", r"mfeavsvc"],
        "processes": ["mcshield.exe", "mfetp.exe"],
    },
    "kaspersky": {
        "patterns": [r"kaspersky", r"klnagent", r"avp"],
        "processes": ["avp.exe", "avpui.exe"],
    },
    "sophos": {
        "patterns": [r"sophos", r"sav32cli", r"swi_fc"],
        "processes": ["savservice.exe", "swi_service.exe"],
    },
}


def detect_security_products(content: str) -> List[Dict[str, Any]]:
    """Detect security products mentioned in content."""
    detected = []
    
    for product, sigs in EDR_SIGNATURES.items():
        for pattern in sigs["patterns"]:
            if re.search(pattern, content, re.IGNORECASE):
                detected.append({
                    "product": product,
                    "type": "edr_av",
                    "pattern_matched": pattern,
                    "processes": sigs["processes"],
                })
                break
    
    return detected
