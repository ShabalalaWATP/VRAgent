"""
Grammar-Based Fuzzing Service

Grammar-based fuzzing engine with DSL for defining input grammars.
Supports recursive generation, mutation at grammar rules, and grammar inference.
"""

import hashlib
import random
import re
import string
import time
from collections import defaultdict
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, AsyncGenerator, Dict, List, Optional, Set, Tuple, Union
import logging
import json

logger = logging.getLogger(__name__)


# =============================================================================
# Data Classes
# =============================================================================

class RuleType(str, Enum):
    """Types of grammar rules."""
    SEQUENCE = "sequence"       # Ordered sequence of symbols
    CHOICE = "choice"           # One of multiple alternatives
    REPEAT = "repeat"           # Repeat 0 or more times
    REPEAT_PLUS = "repeat_plus" # Repeat 1 or more times
    OPTIONAL = "optional"       # 0 or 1 occurrence
    CHARSET = "charset"         # Character set
    REGEX = "regex"             # Regular expression terminal
    LITERAL = "literal"         # Literal string
    RANGE = "range"             # Numeric or character range


@dataclass
class Terminal:
    """A terminal symbol in the grammar."""
    name: str
    type: RuleType
    value: Any  # charset string, regex pattern, literal, or range tuple
    weight: float = 1.0


@dataclass
class GrammarRule:
    """A grammar production rule."""
    name: str
    productions: List[Union[str, List[str]]]  # List of alternatives
    type: RuleType = RuleType.CHOICE
    weight: float = 1.0
    max_recursion: int = 10
    min_length: int = 0
    max_length: int = 1000


@dataclass
class Grammar:
    """Complete grammar definition."""
    name: str
    start_symbol: str
    rules: Dict[str, GrammarRule]
    terminals: Dict[str, Terminal]
    max_depth: int = 20
    max_size: int = 100000
    description: str = ""


@dataclass
class DerivationNode:
    """Node in a derivation tree."""
    symbol: str
    children: List['DerivationNode'] = field(default_factory=list)
    value: Optional[str] = None  # For terminals
    depth: int = 0


@dataclass
class GeneratedInput:
    """A generated input with its derivation tree."""
    data: bytes
    derivation_tree: DerivationNode
    depth: int
    rules_used: List[str]
    size: int
    generation_time_ms: float


@dataclass
class GrammarFuzzConfig:
    """Configuration for grammar-based fuzzing."""
    grammar: Grammar
    min_length: int = 1
    max_length: int = 10000
    mutation_rate: float = 0.1
    crossover_rate: float = 0.2
    max_depth: int = 20
    unique_only: bool = True
    seed: Optional[int] = None


@dataclass
class GrammarMutation:
    """A mutation operation on a generated input."""
    original: GeneratedInput
    mutated: GeneratedInput
    mutation_type: str
    rule_mutated: Optional[str] = None
    details: Dict[str, Any] = field(default_factory=dict)


# =============================================================================
# Built-in Grammars
# =============================================================================

BUILTIN_GRAMMARS: Dict[str, Dict[str, Any]] = {
    "json": {
        "name": "json_grammar",
        "start": "value",
        "rules": {
            "value": {"type": "choice", "productions": ["object", "array", "string", "number", "true", "false", "null"]},
            "object": {"type": "sequence", "productions": ["{", "members_opt", "}"]},
            "members_opt": {"type": "optional", "productions": ["members"]},
            "members": {"type": "choice", "productions": [["pair"], ["pair", ",", "members"]]},
            "pair": {"type": "sequence", "productions": ["string", ":", "value"]},
            "array": {"type": "sequence", "productions": ["[", "elements_opt", "]"]},
            "elements_opt": {"type": "optional", "productions": ["elements"]},
            "elements": {"type": "choice", "productions": [["value"], ["value", ",", "elements"]]},
            "string": {"type": "sequence", "productions": ["\"", "chars", "\""]},
            "chars": {"type": "repeat", "productions": ["char"]},
            "char": {"type": "charset", "value": "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_- "},
            "number": {"type": "regex", "value": r"-?[0-9]+(\.[0-9]+)?([eE][+-]?[0-9]+)?"},
            "true": {"type": "literal", "value": "true"},
            "false": {"type": "literal", "value": "false"},
            "null": {"type": "literal", "value": "null"},
        },
        "terminals": {
            "{": {"type": "literal", "value": "{"},
            "}": {"type": "literal", "value": "}"},
            "[": {"type": "literal", "value": "["},
            "]": {"type": "literal", "value": "]"},
            ":": {"type": "literal", "value": ":"},
            ",": {"type": "literal", "value": ","},
            "\"": {"type": "literal", "value": "\""},
        },
        "description": "JSON data format grammar",
    },
    "xml": {
        "name": "xml_grammar",
        "start": "document",
        "rules": {
            "document": {"type": "sequence", "productions": ["prolog_opt", "element"]},
            "prolog_opt": {"type": "optional", "productions": ["prolog"]},
            "prolog": {"type": "literal", "value": "<?xml version=\"1.0\"?>"},
            "element": {"type": "choice", "productions": ["empty_element", "element_with_content"]},
            "empty_element": {"type": "sequence", "productions": ["<", "name", "attributes", "/>"]},
            "element_with_content": {"type": "sequence", "productions": ["<", "name", "attributes", ">", "content", "</", "name", ">"]},
            "attributes": {"type": "repeat", "productions": ["attribute"]},
            "attribute": {"type": "sequence", "productions": [" ", "name", "=", "\"", "attr_value", "\""]},
            "content": {"type": "choice", "productions": ["text", "element", ["text", "element", "content"]]},
            "name": {"type": "regex", "value": r"[a-zA-Z_][a-zA-Z0-9_-]*"},
            "attr_value": {"type": "charset", "value": "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_- "},
            "text": {"type": "charset", "value": "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789 .,!?"},
        },
        "terminals": {
            "<": {"type": "literal", "value": "<"},
            ">": {"type": "literal", "value": ">"},
            "</": {"type": "literal", "value": "</"},
            "/>": {"type": "literal", "value": "/>"},
            "=": {"type": "literal", "value": "="},
            "\"": {"type": "literal", "value": "\""},
            " ": {"type": "literal", "value": " "},
        },
        "description": "XML markup language grammar",
    },
    "html": {
        "name": "html_grammar",
        "start": "document",
        "rules": {
            "document": {"type": "sequence", "productions": ["doctype", "html"]},
            "doctype": {"type": "literal", "value": "<!DOCTYPE html>"},
            "html": {"type": "sequence", "productions": ["<html>", "head", "body", "</html>"]},
            "head": {"type": "sequence", "productions": ["<head>", "head_content", "</head>"]},
            "head_content": {"type": "choice", "productions": ["title", ["title", "meta"]]},
            "title": {"type": "sequence", "productions": ["<title>", "text", "</title>"]},
            "meta": {"type": "literal", "value": "<meta charset=\"utf-8\">"},
            "body": {"type": "sequence", "productions": ["<body>", "body_content", "</body>"]},
            "body_content": {"type": "repeat", "productions": ["element"]},
            "element": {"type": "choice", "productions": ["div", "p", "span", "a", "script"]},
            "div": {"type": "sequence", "productions": ["<div>", "content", "</div>"]},
            "p": {"type": "sequence", "productions": ["<p>", "text", "</p>"]},
            "span": {"type": "sequence", "productions": ["<span>", "text", "</span>"]},
            "a": {"type": "sequence", "productions": ["<a href=\"", "url", "\">", "text", "</a>"]},
            "script": {"type": "sequence", "productions": ["<script>", "js_code", "</script>"]},
            "content": {"type": "choice", "productions": ["text", "element", ["text", "element"]]},
            "text": {"type": "charset", "value": "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789 .,!?"},
            "url": {"type": "regex", "value": r"https?://[a-z0-9.]+/[a-z0-9/]*"},
            "js_code": {"type": "charset", "value": "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789();=+- "},
        },
        "terminals": {
            "<html>": {"type": "literal", "value": "<html>"},
            "</html>": {"type": "literal", "value": "</html>"},
            "<head>": {"type": "literal", "value": "<head>"},
            "</head>": {"type": "literal", "value": "</head>"},
            "<body>": {"type": "literal", "value": "<body>"},
            "</body>": {"type": "literal", "value": "</body>"},
            "<div>": {"type": "literal", "value": "<div>"},
            "</div>": {"type": "literal", "value": "</div>"},
            "<p>": {"type": "literal", "value": "<p>"},
            "</p>": {"type": "literal", "value": "</p>"},
            "<span>": {"type": "literal", "value": "<span>"},
            "</span>": {"type": "literal", "value": "</span>"},
            "<title>": {"type": "literal", "value": "<title>"},
            "</title>": {"type": "literal", "value": "</title>"},
            "<script>": {"type": "literal", "value": "<script>"},
            "</script>": {"type": "literal", "value": "</script>"},
        },
        "description": "HTML document grammar",
    },
    "sql": {
        "name": "sql_grammar",
        "start": "statement",
        "rules": {
            "statement": {"type": "choice", "productions": ["select", "insert", "update", "delete"]},
            "select": {"type": "sequence", "productions": ["SELECT ", "columns", " FROM ", "table", "where_opt"]},
            "insert": {"type": "sequence", "productions": ["INSERT INTO ", "table", " VALUES ", "(", "values", ")"]},
            "update": {"type": "sequence", "productions": ["UPDATE ", "table", " SET ", "assignments", "where_opt"]},
            "delete": {"type": "sequence", "productions": ["DELETE FROM ", "table", "where_opt"]},
            "columns": {"type": "choice", "productions": ["*", "column_list"]},
            "column_list": {"type": "choice", "productions": [["column"], ["column", ", ", "column_list"]]},
            "column": {"type": "regex", "value": r"[a-z_][a-z0-9_]*"},
            "table": {"type": "regex", "value": r"[a-z_][a-z0-9_]*"},
            "where_opt": {"type": "optional", "productions": ["where"]},
            "where": {"type": "sequence", "productions": [" WHERE ", "condition"]},
            "condition": {"type": "choice", "productions": ["comparison", ["comparison", " AND ", "condition"], ["comparison", " OR ", "condition"]]},
            "comparison": {"type": "sequence", "productions": ["column", "operator", "value"]},
            "operator": {"type": "choice", "productions": ["=", "!=", "<", ">", "<=", ">=", " LIKE "]},
            "value": {"type": "choice", "productions": ["number", "string_value"]},
            "number": {"type": "regex", "value": r"-?[0-9]+"},
            "string_value": {"type": "sequence", "productions": ["'", "string_content", "'"]},
            "string_content": {"type": "charset", "value": "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789 _-"},
            "values": {"type": "choice", "productions": [["value"], ["value", ", ", "values"]]},
            "assignments": {"type": "choice", "productions": [["assignment"], ["assignment", ", ", "assignments"]]},
            "assignment": {"type": "sequence", "productions": ["column", "=", "value"]},
        },
        "terminals": {
            "SELECT ": {"type": "literal", "value": "SELECT "},
            " FROM ": {"type": "literal", "value": " FROM "},
            "INSERT INTO ": {"type": "literal", "value": "INSERT INTO "},
            " VALUES ": {"type": "literal", "value": " VALUES "},
            "UPDATE ": {"type": "literal", "value": "UPDATE "},
            " SET ": {"type": "literal", "value": " SET "},
            "DELETE FROM ": {"type": "literal", "value": "DELETE FROM "},
            " WHERE ": {"type": "literal", "value": " WHERE "},
            " AND ": {"type": "literal", "value": " AND "},
            " OR ": {"type": "literal", "value": " OR "},
            " LIKE ": {"type": "literal", "value": " LIKE "},
            "(": {"type": "literal", "value": "("},
            ")": {"type": "literal", "value": ")"},
            "'": {"type": "literal", "value": "'"},
            ", ": {"type": "literal", "value": ", "},
            "*": {"type": "literal", "value": "*"},
            "=": {"type": "literal", "value": "="},
            "!=": {"type": "literal", "value": "!="},
            "<": {"type": "literal", "value": "<"},
            ">": {"type": "literal", "value": ">"},
            "<=": {"type": "literal", "value": "<="},
            ">=": {"type": "literal", "value": ">="},
        },
        "description": "SQL query language grammar",
    },
    "url": {
        "name": "url_grammar",
        "start": "url",
        "rules": {
            "url": {"type": "sequence", "productions": ["scheme", "://", "authority", "path_opt", "query_opt", "fragment_opt"]},
            "scheme": {"type": "choice", "productions": ["http", "https", "ftp", "file"]},
            "authority": {"type": "sequence", "productions": ["userinfo_opt", "host", "port_opt"]},
            "userinfo_opt": {"type": "optional", "productions": ["userinfo"]},
            "userinfo": {"type": "sequence", "productions": ["username", ":", "password", "@"]},
            "username": {"type": "regex", "value": r"[a-zA-Z0-9_]+"},
            "password": {"type": "regex", "value": r"[a-zA-Z0-9_]+"},
            "host": {"type": "choice", "productions": ["hostname", "ip_address"]},
            "hostname": {"type": "regex", "value": r"[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?)*"},
            "ip_address": {"type": "regex", "value": r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}"},
            "port_opt": {"type": "optional", "productions": ["port"]},
            "port": {"type": "sequence", "productions": [":", "port_number"]},
            "port_number": {"type": "regex", "value": r"[0-9]{1,5}"},
            "path_opt": {"type": "optional", "productions": ["path"]},
            "path": {"type": "repeat_plus", "productions": ["path_segment"]},
            "path_segment": {"type": "sequence", "productions": ["/", "segment"]},
            "segment": {"type": "regex", "value": r"[a-zA-Z0-9._~-]*"},
            "query_opt": {"type": "optional", "productions": ["query"]},
            "query": {"type": "sequence", "productions": ["?", "query_params"]},
            "query_params": {"type": "choice", "productions": [["query_param"], ["query_param", "&", "query_params"]]},
            "query_param": {"type": "sequence", "productions": ["param_name", "=", "param_value"]},
            "param_name": {"type": "regex", "value": r"[a-zA-Z_][a-zA-Z0-9_]*"},
            "param_value": {"type": "regex", "value": r"[a-zA-Z0-9_%-]*"},
            "fragment_opt": {"type": "optional", "productions": ["fragment"]},
            "fragment": {"type": "sequence", "productions": ["#", "fragment_id"]},
            "fragment_id": {"type": "regex", "value": r"[a-zA-Z0-9_-]*"},
        },
        "terminals": {
            "://": {"type": "literal", "value": "://"},
            "http": {"type": "literal", "value": "http"},
            "https": {"type": "literal", "value": "https"},
            "ftp": {"type": "literal", "value": "ftp"},
            "file": {"type": "literal", "value": "file"},
            ":": {"type": "literal", "value": ":"},
            "@": {"type": "literal", "value": "@"},
            "/": {"type": "literal", "value": "/"},
            "?": {"type": "literal", "value": "?"},
            "&": {"type": "literal", "value": "&"},
            "=": {"type": "literal", "value": "="},
            "#": {"type": "literal", "value": "#"},
        },
        "description": "URL grammar (RFC 3986 simplified)",
    },
    "email": {
        "name": "email_grammar",
        "start": "email",
        "rules": {
            "email": {"type": "sequence", "productions": ["local_part", "@", "domain"]},
            "local_part": {"type": "choice", "productions": ["simple_local", "quoted_local"]},
            "simple_local": {"type": "regex", "value": r"[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+"},
            "quoted_local": {"type": "sequence", "productions": ["\"", "quoted_content", "\""]},
            "quoted_content": {"type": "charset", "value": "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789 .@"},
            "domain": {"type": "choice", "productions": ["hostname", "ip_literal"]},
            "hostname": {"type": "regex", "value": r"[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?)+"},
            "ip_literal": {"type": "sequence", "productions": ["[", "ip_address", "]"]},
            "ip_address": {"type": "regex", "value": r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}"},
        },
        "terminals": {
            "@": {"type": "literal", "value": "@"},
            "\"": {"type": "literal", "value": "\""},
            "[": {"type": "literal", "value": "["},
            "]": {"type": "literal", "value": "]"},
        },
        "description": "Email address grammar (RFC 5321 simplified)",
    },
    "javascript": {
        "name": "javascript_grammar",
        "start": "program",
        "rules": {
            "program": {"type": "repeat", "productions": ["statement"]},
            "statement": {"type": "choice", "productions": ["var_decl", "func_decl", "expr_stmt", "if_stmt", "return_stmt"]},
            "var_decl": {"type": "sequence", "productions": ["var ", "identifier", " = ", "expression", ";"]},
            "func_decl": {"type": "sequence", "productions": ["function ", "identifier", "(", "params_opt", ") {", "program", "}"]},
            "params_opt": {"type": "optional", "productions": ["params"]},
            "params": {"type": "choice", "productions": [["identifier"], ["identifier", ", ", "params"]]},
            "expr_stmt": {"type": "sequence", "productions": ["expression", ";"]},
            "if_stmt": {"type": "sequence", "productions": ["if (", "expression", ") {", "program", "}"]},
            "return_stmt": {"type": "sequence", "productions": ["return ", "expression", ";"]},
            "expression": {"type": "choice", "productions": ["literal", "identifier", "binary_expr", "call_expr"]},
            "binary_expr": {"type": "sequence", "productions": ["expression", " ", "operator", " ", "expression"]},
            "call_expr": {"type": "sequence", "productions": ["identifier", "(", "args_opt", ")"]},
            "args_opt": {"type": "optional", "productions": ["args"]},
            "args": {"type": "choice", "productions": [["expression"], ["expression", ", ", "args"]]},
            "literal": {"type": "choice", "productions": ["number", "string_lit", "true", "false", "null"]},
            "number": {"type": "regex", "value": r"-?[0-9]+(\.[0-9]+)?"},
            "string_lit": {"type": "sequence", "productions": ["\"", "string_content", "\""]},
            "string_content": {"type": "charset", "value": "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789 _-"},
            "identifier": {"type": "regex", "value": r"[a-zA-Z_$][a-zA-Z0-9_$]*"},
            "operator": {"type": "choice", "productions": ["+", "-", "*", "/", "==", "!=", "<", ">", "&&", "||"]},
            "true": {"type": "literal", "value": "true"},
            "false": {"type": "literal", "value": "false"},
            "null": {"type": "literal", "value": "null"},
        },
        "terminals": {
            "var ": {"type": "literal", "value": "var "},
            " = ": {"type": "literal", "value": " = "},
            ";": {"type": "literal", "value": ";"},
            "function ": {"type": "literal", "value": "function "},
            "(": {"type": "literal", "value": "("},
            ")": {"type": "literal", "value": ")"},
            ") {": {"type": "literal", "value": ") {"},
            "}": {"type": "literal", "value": "}"},
            ", ": {"type": "literal", "value": ", "},
            "if (": {"type": "literal", "value": "if ("},
            "return ": {"type": "literal", "value": "return "},
            " ": {"type": "literal", "value": " "},
            "\"": {"type": "literal", "value": "\""},
            "+": {"type": "literal", "value": "+"},
            "-": {"type": "literal", "value": "-"},
            "*": {"type": "literal", "value": "*"},
            "/": {"type": "literal", "value": "/"},
            "==": {"type": "literal", "value": "=="},
            "!=": {"type": "literal", "value": "!="},
            "<": {"type": "literal", "value": "<"},
            ">": {"type": "literal", "value": ">"},
            "&&": {"type": "literal", "value": "&&"},
            "||": {"type": "literal", "value": "||"},
        },
        "description": "JavaScript subset grammar",
    },
    "css": {
        "name": "css_grammar",
        "start": "stylesheet",
        "rules": {
            "stylesheet": {"type": "repeat", "productions": ["rule"]},
            "rule": {"type": "sequence", "productions": ["selector", " {", "declarations", "}"]},
            "selector": {"type": "choice", "productions": ["element", "class", "id", "universal"]},
            "element": {"type": "regex", "value": r"[a-z][a-z0-9]*"},
            "class": {"type": "sequence", "productions": [".", "classname"]},
            "classname": {"type": "regex", "value": r"[a-zA-Z_-][a-zA-Z0-9_-]*"},
            "id": {"type": "sequence", "productions": ["#", "idname"]},
            "idname": {"type": "regex", "value": r"[a-zA-Z_-][a-zA-Z0-9_-]*"},
            "universal": {"type": "literal", "value": "*"},
            "declarations": {"type": "repeat", "productions": ["declaration"]},
            "declaration": {"type": "sequence", "productions": ["property", ": ", "value", ";"]},
            "property": {"type": "regex", "value": r"[a-z-]+"},
            "value": {"type": "choice", "productions": ["color", "size", "keyword"]},
            "color": {"type": "choice", "productions": ["hex_color", "rgb_color", "color_name"]},
            "hex_color": {"type": "regex", "value": r"#[0-9a-fA-F]{3,6}"},
            "rgb_color": {"type": "sequence", "productions": ["rgb(", "number", ", ", "number", ", ", "number", ")"]},
            "color_name": {"type": "choice", "productions": ["red", "blue", "green", "white", "black"]},
            "size": {"type": "sequence", "productions": ["number", "unit"]},
            "number": {"type": "regex", "value": r"-?[0-9]+(\.[0-9]+)?"},
            "unit": {"type": "choice", "productions": ["px", "em", "rem", "%", "vh", "vw"]},
            "keyword": {"type": "choice", "productions": ["auto", "none", "block", "flex", "inherit"]},
        },
        "terminals": {
            " {": {"type": "literal", "value": " {"},
            "}": {"type": "literal", "value": "}"},
            ".": {"type": "literal", "value": "."},
            "#": {"type": "literal", "value": "#"},
            ": ": {"type": "literal", "value": ": "},
            ";": {"type": "literal", "value": ";"},
            "rgb(": {"type": "literal", "value": "rgb("},
            ")": {"type": "literal", "value": ")"},
            ", ": {"type": "literal", "value": ", "},
            "px": {"type": "literal", "value": "px"},
            "em": {"type": "literal", "value": "em"},
            "rem": {"type": "literal", "value": "rem"},
            "%": {"type": "literal", "value": "%"},
            "vh": {"type": "literal", "value": "vh"},
            "vw": {"type": "literal", "value": "vw"},
            "red": {"type": "literal", "value": "red"},
            "blue": {"type": "literal", "value": "blue"},
            "green": {"type": "literal", "value": "green"},
            "white": {"type": "literal", "value": "white"},
            "black": {"type": "literal", "value": "black"},
            "auto": {"type": "literal", "value": "auto"},
            "none": {"type": "literal", "value": "none"},
            "block": {"type": "literal", "value": "block"},
            "flex": {"type": "literal", "value": "flex"},
            "inherit": {"type": "literal", "value": "inherit"},
        },
        "description": "CSS stylesheet grammar",
    },
}


# =============================================================================
# Grammar Fuzzer Service
# =============================================================================

class GrammarFuzzerService:
    """Grammar-based fuzzing engine with DSL support."""

    def __init__(self, grammar: Optional[Grammar] = None, seed: Optional[int] = None):
        self.grammar = grammar
        self._recursion_depth: Dict[str, int] = defaultdict(int)
        self._rules_used: List[str] = []
        self._current_depth = 0
        self._generated_size = 0
        if seed is not None:
            random.seed(seed)

    def load_grammar(self, grammar_json: Dict[str, Any]) -> Grammar:
        """Load a grammar from JSON definition."""
        rules = {}
        terminals = {}

        # Parse rules
        for name, rule_def in grammar_json.get("rules", {}).items():
            if isinstance(rule_def, dict):
                rule_type = RuleType(rule_def.get("type", "choice"))

                if rule_type in (RuleType.LITERAL, RuleType.CHARSET, RuleType.REGEX):
                    # This is actually a terminal
                    terminals[name] = Terminal(
                        name=name,
                        type=rule_type,
                        value=rule_def.get("value", ""),
                        weight=rule_def.get("weight", 1.0),
                    )
                else:
                    rules[name] = GrammarRule(
                        name=name,
                        productions=rule_def.get("productions", []),
                        type=rule_type,
                        weight=rule_def.get("weight", 1.0),
                        max_recursion=rule_def.get("max_recursion", 10),
                    )
            elif isinstance(rule_def, list):
                rules[name] = GrammarRule(
                    name=name,
                    productions=rule_def,
                    type=RuleType.CHOICE,
                )

        # Parse explicit terminals
        for name, term_def in grammar_json.get("terminals", {}).items():
            if isinstance(term_def, dict):
                terminals[name] = Terminal(
                    name=name,
                    type=RuleType(term_def.get("type", "literal")),
                    value=term_def.get("value", name),
                )
            else:
                terminals[name] = Terminal(
                    name=name,
                    type=RuleType.LITERAL,
                    value=term_def,
                )

        # Apply weights from grammar_json
        weights = grammar_json.get("weights", {})
        for rule_name, weight in weights.items():
            if rule_name in rules:
                rules[rule_name].weight = weight

        grammar = Grammar(
            name=grammar_json.get("name", "custom_grammar"),
            start_symbol=grammar_json.get("start", "start"),
            rules=rules,
            terminals=terminals,
            max_depth=grammar_json.get("max_depth", 20),
            max_size=grammar_json.get("max_size", 100000),
            description=grammar_json.get("description", ""),
        )

        self.grammar = grammar
        return grammar

    def generate(self, count: int = 1) -> List[GeneratedInput]:
        """Generate inputs from the grammar."""
        if not self.grammar:
            raise ValueError("No grammar loaded")

        inputs = []
        seen_hashes: Set[str] = set()

        attempts = 0
        max_attempts = count * 10

        while len(inputs) < count and attempts < max_attempts:
            attempts += 1
            start_time = time.time()

            # Reset state
            self._recursion_depth.clear()
            self._rules_used = []
            self._current_depth = 0
            self._generated_size = 0

            # Generate derivation tree
            tree = self._derive(self.grammar.start_symbol, 0)
            if tree is None:
                continue

            # Flatten tree to string
            result = self._flatten_tree(tree)
            data = result.encode("utf-8", errors="ignore")

            # Check uniqueness
            data_hash = hashlib.md5(data).hexdigest()
            if data_hash in seen_hashes:
                continue
            seen_hashes.add(data_hash)

            generation_time_ms = (time.time() - start_time) * 1000

            inputs.append(GeneratedInput(
                data=data,
                derivation_tree=tree,
                depth=self._current_depth,
                rules_used=list(set(self._rules_used)),
                size=len(data),
                generation_time_ms=generation_time_ms,
            ))

        return inputs

    def _derive(self, symbol: str, depth: int) -> Optional[DerivationNode]:
        """Derive a symbol recursively."""
        self._current_depth = max(self._current_depth, depth)

        # Check limits
        if depth > self.grammar.max_depth:
            return None
        if self._generated_size > self.grammar.max_size:
            return None

        # Check if it's a terminal
        if symbol in self.grammar.terminals:
            terminal = self.grammar.terminals[symbol]
            value = self._generate_terminal(terminal)
            self._generated_size += len(value)
            return DerivationNode(symbol=symbol, value=value, depth=depth)

        # Check if it's a rule
        if symbol not in self.grammar.rules:
            # Treat as literal terminal
            self._generated_size += len(symbol)
            return DerivationNode(symbol=symbol, value=symbol, depth=depth)

        rule = self.grammar.rules[symbol]
        self._rules_used.append(symbol)

        # Check recursion limit
        if self._recursion_depth[symbol] >= rule.max_recursion:
            # Try to find a non-recursive alternative or return minimal
            return self._derive_minimal(symbol, depth)

        self._recursion_depth[symbol] += 1

        try:
            node = DerivationNode(symbol=symbol, depth=depth)

            if rule.type == RuleType.CHOICE:
                # Choose one production
                production = self._weighted_choice(rule.productions, rule)
                children = self._derive_production(production, depth + 1)
                if children is None:
                    return None
                node.children = children

            elif rule.type == RuleType.SEQUENCE:
                # All symbols in sequence
                children = self._derive_production(rule.productions, depth + 1)
                if children is None:
                    return None
                node.children = children

            elif rule.type == RuleType.REPEAT:
                # Zero or more repetitions
                count = random.randint(0, min(5, rule.max_recursion - self._recursion_depth[symbol]))
                for _ in range(count):
                    production = rule.productions[0] if rule.productions else symbol
                    children = self._derive_production([production] if isinstance(production, str) else production, depth + 1)
                    if children:
                        node.children.extend(children)

            elif rule.type == RuleType.REPEAT_PLUS:
                # One or more repetitions
                count = random.randint(1, min(5, rule.max_recursion - self._recursion_depth[symbol] + 1))
                for _ in range(count):
                    production = rule.productions[0] if rule.productions else symbol
                    children = self._derive_production([production] if isinstance(production, str) else production, depth + 1)
                    if children:
                        node.children.extend(children)

            elif rule.type == RuleType.OPTIONAL:
                # Zero or one occurrence
                if random.random() > 0.5:
                    production = rule.productions[0] if rule.productions else []
                    children = self._derive_production([production] if isinstance(production, str) else production, depth + 1)
                    if children:
                        node.children = children

            elif rule.type in (RuleType.CHARSET, RuleType.REGEX, RuleType.LITERAL):
                # Terminal rule
                value = self._generate_from_rule(rule)
                node.value = value
                self._generated_size += len(value)

            return node

        finally:
            self._recursion_depth[symbol] -= 1

    def _derive_minimal(self, symbol: str, depth: int) -> Optional[DerivationNode]:
        """Generate minimal derivation to avoid infinite recursion."""
        if symbol in self.grammar.terminals:
            terminal = self.grammar.terminals[symbol]
            value = self._generate_terminal(terminal)
            return DerivationNode(symbol=symbol, value=value, depth=depth)

        # Return empty for recursive rules at limit
        return DerivationNode(symbol=symbol, value="", depth=depth)

    def _derive_production(self, production: Union[str, List[str]], depth: int) -> Optional[List[DerivationNode]]:
        """Derive a production (sequence of symbols)."""
        if isinstance(production, str):
            production = [production]

        children = []
        for symbol in production:
            child = self._derive(symbol, depth)
            if child is None:
                return None
            children.append(child)

        return children

    def _weighted_choice(self, productions: List[Any], rule: GrammarRule) -> Any:
        """Choose a production with optional weighting."""
        if not productions:
            return ""

        # Simple random choice for now
        # Could be enhanced with weights per production
        return random.choice(productions)

    def _generate_terminal(self, terminal: Terminal) -> str:
        """Generate value for a terminal."""
        if terminal.type == RuleType.LITERAL:
            return str(terminal.value)

        elif terminal.type == RuleType.CHARSET:
            charset = str(terminal.value)
            length = random.randint(1, 10)
            return "".join(random.choice(charset) for _ in range(length))

        elif terminal.type == RuleType.REGEX:
            return self._generate_from_regex(str(terminal.value))

        elif terminal.type == RuleType.RANGE:
            if isinstance(terminal.value, tuple) and len(terminal.value) == 2:
                return str(random.randint(terminal.value[0], terminal.value[1]))

        return str(terminal.value)

    def _generate_from_rule(self, rule: GrammarRule) -> str:
        """Generate value directly from a rule (for terminal-like rules)."""
        if rule.type == RuleType.LITERAL:
            return rule.productions[0] if rule.productions else ""
        elif rule.type == RuleType.CHARSET:
            charset = rule.productions[0] if rule.productions else string.ascii_letters
            length = random.randint(1, 10)
            return "".join(random.choice(charset) for _ in range(length))
        elif rule.type == RuleType.REGEX:
            pattern = rule.productions[0] if rule.productions else ".*"
            return self._generate_from_regex(pattern)
        return ""

    def _generate_from_regex(self, pattern: str) -> str:
        """Generate a string matching a regex pattern (simplified)."""
        # Simplified regex generation - handles common patterns
        result = []
        i = 0

        while i < len(pattern):
            c = pattern[i]

            if c == "\\":
                if i + 1 < len(pattern):
                    next_c = pattern[i + 1]
                    if next_c == "d":
                        result.append(random.choice(string.digits))
                    elif next_c == "w":
                        result.append(random.choice(string.ascii_letters + string.digits + "_"))
                    elif next_c == "s":
                        result.append(" ")
                    elif next_c == ".":
                        result.append(".")
                    else:
                        result.append(next_c)
                    i += 2
                else:
                    i += 1

            elif c == "[":
                # Character class
                end = pattern.find("]", i)
                if end != -1:
                    char_class = pattern[i+1:end]
                    # Handle ranges like a-z
                    chars = []
                    j = 0
                    while j < len(char_class):
                        if j + 2 < len(char_class) and char_class[j + 1] == "-":
                            start_c = char_class[j]
                            end_c = char_class[j + 2]
                            chars.extend(chr(c) for c in range(ord(start_c), ord(end_c) + 1))
                            j += 3
                        else:
                            chars.append(char_class[j])
                            j += 1
                    if chars:
                        result.append(random.choice(chars))
                    i = end + 1
                else:
                    result.append(c)
                    i += 1

            elif c in "?*+":
                # Quantifiers - already handled by previous char
                i += 1

            elif c == "{":
                # Range quantifier {n,m}
                end = pattern.find("}", i)
                if end != -1:
                    i = end + 1
                else:
                    i += 1

            elif c == "(":
                # Group - skip for simplicity
                depth = 1
                i += 1
                while i < len(pattern) and depth > 0:
                    if pattern[i] == "(":
                        depth += 1
                    elif pattern[i] == ")":
                        depth -= 1
                    i += 1

            elif c == ".":
                result.append(random.choice(string.ascii_letters + string.digits))
                i += 1

            elif c == "^" or c == "$":
                i += 1

            else:
                result.append(c)
                i += 1

        return "".join(result)

    def _flatten_tree(self, node: DerivationNode) -> str:
        """Flatten derivation tree to string."""
        if node.value is not None:
            return node.value

        return "".join(self._flatten_tree(child) for child in node.children)

    # =========================================================================
    # Mutation Operations
    # =========================================================================

    def mutate_at_rule(self, input_: GeneratedInput, rule: Optional[str] = None) -> GrammarMutation:
        """Mutate an input at a specific grammar rule."""
        if not self.grammar:
            raise ValueError("No grammar loaded")

        # Find nodes matching the rule
        nodes = self._find_nodes_by_rule(input_.derivation_tree, rule)
        if not nodes:
            # Fall back to random mutation
            return self._random_mutation(input_)

        # Pick a random node to mutate
        node_to_mutate = random.choice(nodes)

        # Re-derive that subtree
        self._recursion_depth.clear()
        self._rules_used = []
        self._current_depth = 0
        self._generated_size = 0

        new_subtree = self._derive(node_to_mutate.symbol, node_to_mutate.depth)

        if new_subtree is None:
            return self._random_mutation(input_)

        # Create new tree with mutated subtree
        new_tree = self._replace_node(input_.derivation_tree, node_to_mutate, new_subtree)

        # Flatten to get new data
        result = self._flatten_tree(new_tree)
        data = result.encode("utf-8", errors="ignore")

        mutated_input = GeneratedInput(
            data=data,
            derivation_tree=new_tree,
            depth=self._calculate_depth(new_tree),
            rules_used=self._collect_rules(new_tree),
            size=len(data),
            generation_time_ms=0,
        )

        return GrammarMutation(
            original=input_,
            mutated=mutated_input,
            mutation_type="rule_mutation",
            rule_mutated=rule or node_to_mutate.symbol,
        )

    def _random_mutation(self, input_: GeneratedInput) -> GrammarMutation:
        """Apply a random mutation to the input."""
        data = bytearray(input_.data)

        mutation_type = random.choice(["bit_flip", "byte_flip", "insert", "delete"])

        if mutation_type == "bit_flip" and data:
            pos = random.randint(0, len(data) - 1)
            bit = random.randint(0, 7)
            data[pos] ^= (1 << bit)

        elif mutation_type == "byte_flip" and data:
            pos = random.randint(0, len(data) - 1)
            data[pos] ^= 0xFF

        elif mutation_type == "insert":
            pos = random.randint(0, len(data))
            data.insert(pos, random.randint(0, 255))

        elif mutation_type == "delete" and len(data) > 1:
            pos = random.randint(0, len(data) - 1)
            del data[pos]

        mutated_input = GeneratedInput(
            data=bytes(data),
            derivation_tree=input_.derivation_tree,  # Keep original tree
            depth=input_.depth,
            rules_used=input_.rules_used,
            size=len(data),
            generation_time_ms=0,
        )

        return GrammarMutation(
            original=input_,
            mutated=mutated_input,
            mutation_type=mutation_type,
        )

    def _find_nodes_by_rule(self, tree: DerivationNode, rule: Optional[str]) -> List[DerivationNode]:
        """Find all nodes in tree matching a rule."""
        results = []

        def search(node: DerivationNode):
            if rule is None or node.symbol == rule:
                if node.symbol in self.grammar.rules:
                    results.append(node)
            for child in node.children:
                search(child)

        search(tree)
        return results

    def _replace_node(self, tree: DerivationNode, old_node: DerivationNode, new_node: DerivationNode) -> DerivationNode:
        """Replace a node in the tree with a new node."""
        if tree is old_node:
            return new_node

        new_tree = DerivationNode(
            symbol=tree.symbol,
            value=tree.value,
            depth=tree.depth,
        )

        for child in tree.children:
            new_tree.children.append(self._replace_node(child, old_node, new_node))

        return new_tree

    def _calculate_depth(self, tree: DerivationNode) -> int:
        """Calculate the depth of a derivation tree."""
        if not tree.children:
            return tree.depth

        return max(self._calculate_depth(child) for child in tree.children)

    def _collect_rules(self, tree: DerivationNode) -> List[str]:
        """Collect all rules used in a derivation tree."""
        rules = set()

        def collect(node: DerivationNode):
            if node.symbol in self.grammar.rules:
                rules.add(node.symbol)
            for child in node.children:
                collect(child)

        collect(tree)
        return list(rules)

    # =========================================================================
    # Crossover
    # =========================================================================

    def crossover(self, a: GeneratedInput, b: GeneratedInput) -> GeneratedInput:
        """Perform crossover between two inputs."""
        if not self.grammar:
            raise ValueError("No grammar loaded")

        # Find common rules
        common_rules = set(a.rules_used) & set(b.rules_used)
        if not common_rules:
            # No common rules, return mutation of a
            return self.mutate_at_rule(a).mutated

        # Pick a common rule
        rule = random.choice(list(common_rules))

        # Find matching nodes
        nodes_a = self._find_nodes_by_rule(a.derivation_tree, rule)
        nodes_b = self._find_nodes_by_rule(b.derivation_tree, rule)

        if not nodes_a or not nodes_b:
            return self.mutate_at_rule(a).mutated

        # Swap a subtree from b into a
        node_a = random.choice(nodes_a)
        node_b = random.choice(nodes_b)

        new_tree = self._replace_node(a.derivation_tree, node_a, node_b)

        result = self._flatten_tree(new_tree)
        data = result.encode("utf-8", errors="ignore")

        return GeneratedInput(
            data=data,
            derivation_tree=new_tree,
            depth=self._calculate_depth(new_tree),
            rules_used=self._collect_rules(new_tree),
            size=len(data),
            generation_time_ms=0,
        )

    # =========================================================================
    # Grammar Inference
    # =========================================================================

    def infer_grammar(self, samples: List[bytes], name: str = "inferred") -> Grammar:
        """Infer a grammar from sample inputs (simplified)."""
        # This is a simplified grammar inference
        # A full implementation would use algorithms like GLADE or learn from parse trees

        rules = {}
        terminals = {}

        # Analyze samples for common patterns
        decoded_samples = [s.decode("utf-8", errors="ignore") for s in samples]

        # Find common prefixes/suffixes
        if decoded_samples:
            common_prefix = self._longest_common_prefix(decoded_samples)
            common_suffix = self._longest_common_suffix(decoded_samples)

            if common_prefix:
                terminals["prefix"] = Terminal(
                    name="prefix",
                    type=RuleType.LITERAL,
                    value=common_prefix,
                )

            if common_suffix:
                terminals["suffix"] = Terminal(
                    name="suffix",
                    type=RuleType.LITERAL,
                    value=common_suffix,
                )

        # Identify character classes used
        all_chars = set()
        for sample in decoded_samples:
            all_chars.update(sample)

        alpha_chars = all_chars & set(string.ascii_letters)
        digit_chars = all_chars & set(string.digits)
        special_chars = all_chars - alpha_chars - digit_chars - set(string.whitespace)

        # Create terminals for character classes
        if alpha_chars:
            terminals["alpha"] = Terminal(
                name="alpha",
                type=RuleType.CHARSET,
                value="".join(sorted(alpha_chars)),
            )

        if digit_chars:
            terminals["digit"] = Terminal(
                name="digit",
                type=RuleType.CHARSET,
                value="".join(sorted(digit_chars)),
            )

        if special_chars:
            terminals["special"] = Terminal(
                name="special",
                type=RuleType.CHARSET,
                value="".join(sorted(special_chars)),
            )

        # Create basic rules
        content_productions = []
        if "alpha" in terminals:
            content_productions.append("alpha")
        if "digit" in terminals:
            content_productions.append("digit")
        if "special" in terminals:
            content_productions.append("special")

        if content_productions:
            rules["content"] = GrammarRule(
                name="content",
                productions=content_productions,
                type=RuleType.CHOICE,
            )

            rules["content_repeat"] = GrammarRule(
                name="content_repeat",
                productions=["content"],
                type=RuleType.REPEAT,
            )

        # Build start rule
        start_productions = []
        if "prefix" in terminals:
            start_productions.append("prefix")
        start_productions.append("content_repeat")
        if "suffix" in terminals:
            start_productions.append("suffix")

        rules["start"] = GrammarRule(
            name="start",
            productions=start_productions if len(start_productions) > 1 else ["content_repeat"],
            type=RuleType.SEQUENCE,
        )

        grammar = Grammar(
            name=name,
            start_symbol="start",
            rules=rules,
            terminals=terminals,
            description=f"Grammar inferred from {len(samples)} samples",
        )

        self.grammar = grammar
        return grammar

    def _longest_common_prefix(self, strings: List[str]) -> str:
        """Find longest common prefix of strings."""
        if not strings:
            return ""

        prefix = strings[0]
        for s in strings[1:]:
            while not s.startswith(prefix):
                prefix = prefix[:-1]
                if not prefix:
                    return ""
        return prefix

    def _longest_common_suffix(self, strings: List[str]) -> str:
        """Find longest common suffix of strings."""
        if not strings:
            return ""

        suffix = strings[0]
        for s in strings[1:]:
            while not s.endswith(suffix):
                suffix = suffix[1:]
                if not suffix:
                    return ""
        return suffix

    # =========================================================================
    # Fuzzing Session
    # =========================================================================

    async def fuzz_with_grammar(
        self,
        callback,
        grammar: Optional[Grammar] = None,
        count: int = 1000,
        mutation_rate: float = 0.3,
        crossover_rate: float = 0.2,
    ) -> AsyncGenerator[Dict[str, Any], None]:
        """Run a grammar-based fuzzing session."""
        if grammar:
            self.grammar = grammar

        if not self.grammar:
            raise ValueError("No grammar loaded")

        # Generate initial population
        population = self.generate(count=min(100, count))

        for i in range(count):
            if random.random() < crossover_rate and len(population) >= 2:
                # Crossover
                a, b = random.sample(population, 2)
                input_ = self.crossover(a, b)
                operation = "crossover"
            elif random.random() < mutation_rate and population:
                # Mutation
                parent = random.choice(population)
                mutation = self.mutate_at_rule(parent)
                input_ = mutation.mutated
                operation = f"mutation:{mutation.mutation_type}"
            else:
                # Generate new
                inputs = self.generate(count=1)
                if not inputs:
                    continue
                input_ = inputs[0]
                operation = "generation"

            # Call the callback with the generated input
            result = await callback(input_.data)

            # Yield progress
            yield {
                "iteration": i + 1,
                "total": count,
                "operation": operation,
                "input_size": input_.size,
                "input_depth": input_.depth,
                "rules_used": input_.rules_used,
                "result": result,
            }

            # Add interesting inputs to population
            if result.get("interesting", False):
                population.append(input_)

                # Keep population bounded
                if len(population) > 200:
                    population = population[-200:]


# =============================================================================
# Helper Functions
# =============================================================================

def get_builtin_grammar(name: str) -> Optional[Dict[str, Any]]:
    """Get a built-in grammar definition by name."""
    return BUILTIN_GRAMMARS.get(name.lower())


def list_builtin_grammars() -> Dict[str, str]:
    """List all available built-in grammars."""
    return {
        name: grammar.get("description", "")
        for name, grammar in BUILTIN_GRAMMARS.items()
    }


def create_grammar_from_builtin(name: str) -> Optional[Grammar]:
    """Create a Grammar object from a built-in grammar."""
    grammar_def = get_builtin_grammar(name)
    if not grammar_def:
        return None

    service = GrammarFuzzerService()
    return service.load_grammar(grammar_def)


def generate_from_builtin(grammar_name: str, count: int = 10) -> List[GeneratedInput]:
    """Generate inputs from a built-in grammar."""
    grammar = create_grammar_from_builtin(grammar_name)
    if not grammar:
        raise ValueError(f"Unknown grammar: {grammar_name}")

    service = GrammarFuzzerService(grammar=grammar)
    return service.generate(count=count)
