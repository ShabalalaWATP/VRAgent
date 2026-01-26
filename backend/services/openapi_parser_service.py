"""
OpenAPI/Swagger Parser Service

Parses OpenAPI 3.x and Swagger 2.x specifications to automatically
discover API endpoints, parameters, and generate fuzzing targets.

Features:
- OpenAPI 3.0/3.1 support
- Swagger 2.0 support
- URL and file-based spec loading
- Automatic parameter type detection
- Security scheme detection
- Example value extraction
- Fuzzing target generation
"""

import json
import logging
import re
import uuid
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional, Set, Tuple, Union
from urllib.parse import urljoin, urlparse
import yaml
import httpx

logger = logging.getLogger(__name__)


class SpecVersion(str, Enum):
    """Supported specification versions."""
    OPENAPI_3_0 = "openapi_3.0"
    OPENAPI_3_1 = "openapi_3.1"
    SWAGGER_2_0 = "swagger_2.0"
    UNKNOWN = "unknown"


class ParameterLocation(str, Enum):
    """Where the parameter is located."""
    PATH = "path"
    QUERY = "query"
    HEADER = "header"
    COOKIE = "cookie"
    BODY = "body"
    FORM = "formData"


class ParameterType(str, Enum):
    """Parameter data types."""
    STRING = "string"
    INTEGER = "integer"
    NUMBER = "number"
    BOOLEAN = "boolean"
    ARRAY = "array"
    OBJECT = "object"
    FILE = "file"


class AuthType(str, Enum):
    """Authentication types detected."""
    API_KEY = "apiKey"
    BEARER = "bearer"
    BASIC = "basic"
    OAUTH2 = "oauth2"
    OPENID = "openIdConnect"
    NONE = "none"


@dataclass
class APIParameter:
    """Represents an API parameter."""
    name: str
    location: ParameterLocation
    param_type: ParameterType
    required: bool = False
    description: str = ""
    example: Optional[Any] = None
    default: Optional[Any] = None
    enum: List[Any] = field(default_factory=list)
    format: Optional[str] = None  # e.g., "email", "uuid", "date-time"
    min_length: Optional[int] = None
    max_length: Optional[int] = None
    pattern: Optional[str] = None
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "location": self.location.value,
            "type": self.param_type.value,
            "required": self.required,
            "description": self.description,
            "example": self.example,
            "default": self.default,
            "enum": self.enum,
            "format": self.format,
        }
    
    def generate_sample_value(self) -> Any:
        """Generate a sample value based on type and constraints."""
        if self.example is not None:
            return self.example
        if self.default is not None:
            return self.default
        if self.enum:
            return self.enum[0]
        
        # Generate based on format
        if self.format:
            format_samples = {
                "email": "test@example.com",
                "uuid": "550e8400-e29b-41d4-a716-446655440000",
                "date": "2024-01-01",
                "date-time": "2024-01-01T00:00:00Z",
                "uri": "https://example.com",
                "hostname": "example.com",
                "ipv4": "192.168.1.1",
                "ipv6": "::1",
                "byte": "dGVzdA==",
                "binary": "test",
                "password": "password123",
                "int32": 1,
                "int64": 1,
                "float": 1.0,
                "double": 1.0,
            }
            if self.format in format_samples:
                return format_samples[self.format]
        
        # Generate based on type
        type_samples = {
            ParameterType.STRING: "test",
            ParameterType.INTEGER: 1,
            ParameterType.NUMBER: 1.0,
            ParameterType.BOOLEAN: True,
            ParameterType.ARRAY: ["test"],
            ParameterType.OBJECT: {"key": "value"},
            ParameterType.FILE: "file.txt",
        }
        return type_samples.get(self.param_type, "test")


@dataclass
class APIEndpoint:
    """Represents an API endpoint."""
    path: str
    method: str
    operation_id: Optional[str] = None
    summary: str = ""
    description: str = ""
    parameters: List[APIParameter] = field(default_factory=list)
    request_body_type: Optional[str] = None  # application/json, multipart/form-data, etc.
    request_body_schema: Optional[Dict] = None
    responses: Dict[str, str] = field(default_factory=dict)  # status_code -> description
    security: List[str] = field(default_factory=list)  # Security scheme names
    tags: List[str] = field(default_factory=list)
    deprecated: bool = False
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "path": self.path,
            "method": self.method,
            "operation_id": self.operation_id,
            "summary": self.summary,
            "description": self.description,
            "parameters": [p.to_dict() for p in self.parameters],
            "request_body_type": self.request_body_type,
            "responses": self.responses,
            "security": self.security,
            "tags": self.tags,
            "deprecated": self.deprecated,
        }
    
    def get_full_url(self, base_url: str) -> str:
        """Get the full URL for this endpoint."""
        return urljoin(base_url.rstrip("/") + "/", self.path.lstrip("/"))
    
    def generate_sample_request(self, base_url: str) -> Dict[str, Any]:
        """Generate a sample request for this endpoint."""
        url = self.get_full_url(base_url)
        
        # Fill path parameters
        for param in self.parameters:
            if param.location == ParameterLocation.PATH:
                url = url.replace(f"{{{param.name}}}", str(param.generate_sample_value()))
        
        # Collect query parameters
        query_params = {}
        for param in self.parameters:
            if param.location == ParameterLocation.QUERY:
                query_params[param.name] = param.generate_sample_value()
        
        # Collect headers
        headers = {}
        for param in self.parameters:
            if param.location == ParameterLocation.HEADER:
                headers[param.name] = str(param.generate_sample_value())
        
        # Generate body
        body = None
        if self.request_body_schema:
            body = self._generate_body_from_schema(self.request_body_schema)
        else:
            for param in self.parameters:
                if param.location == ParameterLocation.BODY:
                    if body is None:
                        body = {}
                    body[param.name] = param.generate_sample_value()
        
        return {
            "url": url,
            "method": self.method.upper(),
            "query_params": query_params,
            "headers": headers,
            "body": body,
            "content_type": self.request_body_type,
        }
    
    def _generate_body_from_schema(self, schema: Dict) -> Any:
        """Generate request body from JSON schema."""
        if not schema:
            return None
        
        schema_type = schema.get("type", "object")
        
        if "example" in schema:
            return schema["example"]
        
        if schema_type == "object":
            result = {}
            properties = schema.get("properties", {})
            for prop_name, prop_schema in properties.items():
                result[prop_name] = self._generate_body_from_schema(prop_schema)
            return result
        
        elif schema_type == "array":
            items = schema.get("items", {})
            return [self._generate_body_from_schema(items)]
        
        elif schema_type == "string":
            fmt = schema.get("format", "")
            if fmt == "email":
                return "test@example.com"
            elif fmt == "date":
                return "2024-01-01"
            elif fmt == "date-time":
                return "2024-01-01T00:00:00Z"
            elif fmt == "uuid":
                return "550e8400-e29b-41d4-a716-446655440000"
            elif "enum" in schema:
                return schema["enum"][0]
            return schema.get("default", "test")
        
        elif schema_type == "integer":
            return schema.get("default", 1)
        
        elif schema_type == "number":
            return schema.get("default", 1.0)
        
        elif schema_type == "boolean":
            return schema.get("default", True)
        
        return None


@dataclass
class SecurityScheme:
    """Represents an API security scheme."""
    name: str
    auth_type: AuthType
    location: Optional[str] = None  # header, query, cookie
    param_name: Optional[str] = None  # e.g., "Authorization", "X-API-Key"
    scheme: Optional[str] = None  # e.g., "bearer", "basic"
    flows: Optional[Dict] = None  # OAuth2 flows
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "type": self.auth_type.value,
            "location": self.location,
            "param_name": self.param_name,
            "scheme": self.scheme,
        }


@dataclass
class ParsedAPISpec:
    """Result of parsing an API specification."""
    id: str = field(default_factory=lambda: uuid.uuid4().hex[:16])
    title: str = ""
    version: str = ""
    description: str = ""
    spec_version: SpecVersion = SpecVersion.UNKNOWN
    base_url: str = ""
    servers: List[str] = field(default_factory=list)
    endpoints: List[APIEndpoint] = field(default_factory=list)
    security_schemes: List[SecurityScheme] = field(default_factory=list)
    tags: Dict[str, str] = field(default_factory=dict)  # tag name -> description
    parsed_at: str = field(default_factory=lambda: datetime.utcnow().isoformat())
    errors: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "title": self.title,
            "version": self.version,
            "description": self.description,
            "spec_version": self.spec_version.value,
            "base_url": self.base_url,
            "servers": self.servers,
            "endpoints_count": len(self.endpoints),
            "endpoints": [e.to_dict() for e in self.endpoints],
            "security_schemes": [s.to_dict() for s in self.security_schemes],
            "tags": self.tags,
            "parsed_at": self.parsed_at,
            "errors": self.errors,
            "warnings": self.warnings,
        }
    
    def get_endpoints_by_tag(self, tag: str) -> List[APIEndpoint]:
        """Get endpoints filtered by tag."""
        return [e for e in self.endpoints if tag in e.tags]
    
    def get_endpoints_by_method(self, method: str) -> List[APIEndpoint]:
        """Get endpoints filtered by HTTP method."""
        return [e for e in self.endpoints if e.method.upper() == method.upper()]
    
    def generate_fuzzing_targets(self) -> List[Dict[str, Any]]:
        """Generate fuzzing targets from parsed endpoints."""
        targets = []
        base_url = self.base_url or (self.servers[0] if self.servers else "http://localhost")
        
        for endpoint in self.endpoints:
            if endpoint.deprecated:
                continue
            
            sample = endpoint.generate_sample_request(base_url)
            
            # Identify fuzzable parameters
            fuzzable_params = []
            for param in endpoint.parameters:
                fuzzable_params.append(param.name)
            
            # Add body fields as fuzzable
            if endpoint.request_body_schema:
                body_params = self._extract_body_params(endpoint.request_body_schema)
                fuzzable_params.extend(body_params)
            
            targets.append({
                "url": sample["url"],
                "method": sample["method"],
                "headers": sample["headers"],
                "body": json.dumps(sample["body"]) if sample["body"] else None,
                "parameters": fuzzable_params,
                "content_type": sample["content_type"],
                "operation_id": endpoint.operation_id,
                "tags": endpoint.tags,
            })
        
        return targets
    
    def _extract_body_params(self, schema: Dict, prefix: str = "") -> List[str]:
        """Extract parameter names from body schema."""
        params = []
        if schema.get("type") == "object":
            for prop_name in schema.get("properties", {}):
                full_name = f"{prefix}.{prop_name}" if prefix else prop_name
                params.append(full_name)
                # Recurse for nested objects
                prop_schema = schema["properties"][prop_name]
                if prop_schema.get("type") == "object":
                    params.extend(self._extract_body_params(prop_schema, full_name))
        return params


class OpenAPIParser:
    """
    Parser for OpenAPI 3.x and Swagger 2.x specifications.
    """
    
    def __init__(self):
        self.spec: Dict = {}
        self.result: ParsedAPISpec = ParsedAPISpec()
        self._resolved_refs: Dict[str, Any] = {}
    
    async def parse_url(self, url: str, headers: Optional[Dict[str, str]] = None, verify_ssl: bool = True) -> ParsedAPISpec:
        """Parse an OpenAPI spec from a URL.

        Args:
            url: URL to fetch the OpenAPI spec from
            headers: Optional HTTP headers
            verify_ssl: Whether to verify SSL certificates (default True)
        """
        try:
            async with httpx.AsyncClient(timeout=30.0, verify=verify_ssl) as client:
                response = await client.get(url, headers=headers or {})
                response.raise_for_status()
                
                content = response.text
                
                # Try to parse as JSON first, then YAML
                try:
                    self.spec = json.loads(content)
                except json.JSONDecodeError:
                    self.spec = yaml.safe_load(content)
                
                # Determine base URL from spec URL if not specified
                parsed_url = urlparse(url)
                default_base = f"{parsed_url.scheme}://{parsed_url.netloc}"
                
                return self._parse_spec(default_base)
                
        except Exception as e:
            logger.error(f"Failed to fetch OpenAPI spec from {url}: {e}")
            self.result.errors.append(f"Failed to fetch spec: {str(e)}")
            return self.result
    
    def parse_content(self, content: str, base_url: str = "") -> ParsedAPISpec:
        """Parse an OpenAPI spec from string content."""
        try:
            # Try JSON first, then YAML
            try:
                self.spec = json.loads(content)
            except json.JSONDecodeError:
                self.spec = yaml.safe_load(content)
            
            return self._parse_spec(base_url)
            
        except Exception as e:
            logger.error(f"Failed to parse OpenAPI spec: {e}")
            self.result.errors.append(f"Failed to parse spec: {str(e)}")
            return self.result
    
    def parse_file(self, filepath: str, base_url: str = "") -> ParsedAPISpec:
        """Parse an OpenAPI spec from a file."""
        try:
            with open(filepath, 'r', encoding='utf-8') as f:
                content = f.read()
            return self.parse_content(content, base_url)
        except Exception as e:
            logger.error(f"Failed to read OpenAPI spec file {filepath}: {e}")
            self.result.errors.append(f"Failed to read file: {str(e)}")
            return self.result
    
    def _parse_spec(self, default_base_url: str = "") -> ParsedAPISpec:
        """Parse the loaded specification."""
        self.result = ParsedAPISpec()
        
        # Detect spec version
        self._detect_version()
        
        # Parse info
        self._parse_info()
        
        # Parse servers/base URL
        self._parse_servers(default_base_url)
        
        # Parse security schemes
        self._parse_security_schemes()
        
        # Parse tags
        self._parse_tags()
        
        # Parse paths/endpoints
        self._parse_paths()
        
        return self.result
    
    def _detect_version(self):
        """Detect the specification version."""
        if "openapi" in self.spec:
            version = self.spec["openapi"]
            if version.startswith("3.1"):
                self.result.spec_version = SpecVersion.OPENAPI_3_1
            elif version.startswith("3."):
                self.result.spec_version = SpecVersion.OPENAPI_3_0
            else:
                self.result.spec_version = SpecVersion.UNKNOWN
                self.result.warnings.append(f"Unknown OpenAPI version: {version}")
        elif "swagger" in self.spec:
            version = self.spec["swagger"]
            if version.startswith("2."):
                self.result.spec_version = SpecVersion.SWAGGER_2_0
            else:
                self.result.spec_version = SpecVersion.UNKNOWN
                self.result.warnings.append(f"Unknown Swagger version: {version}")
        else:
            self.result.spec_version = SpecVersion.UNKNOWN
            self.result.errors.append("Could not detect specification version")
    
    def _parse_info(self):
        """Parse the info section."""
        info = self.spec.get("info", {})
        self.result.title = info.get("title", "Unknown API")
        self.result.version = info.get("version", "")
        self.result.description = info.get("description", "")
    
    def _parse_servers(self, default_base_url: str):
        """Parse servers/host information."""
        if self.result.spec_version in [SpecVersion.OPENAPI_3_0, SpecVersion.OPENAPI_3_1]:
            # OpenAPI 3.x uses servers array
            servers = self.spec.get("servers", [])
            for server in servers:
                url = server.get("url", "")
                # Handle server variables
                variables = server.get("variables", {})
                for var_name, var_info in variables.items():
                    default_value = var_info.get("default", "")
                    url = url.replace(f"{{{var_name}}}", default_value)
                if url:
                    self.result.servers.append(url)
            
            self.result.base_url = self.result.servers[0] if self.result.servers else default_base_url
        
        elif self.result.spec_version == SpecVersion.SWAGGER_2_0:
            # Swagger 2.0 uses host, basePath, schemes
            host = self.spec.get("host", "")
            base_path = self.spec.get("basePath", "")
            schemes = self.spec.get("schemes", ["https"])
            
            if host:
                for scheme in schemes:
                    url = f"{scheme}://{host}{base_path}"
                    self.result.servers.append(url)
            
            self.result.base_url = self.result.servers[0] if self.result.servers else default_base_url
        
        else:
            self.result.base_url = default_base_url
    
    def _parse_security_schemes(self):
        """Parse security scheme definitions."""
        if self.result.spec_version in [SpecVersion.OPENAPI_3_0, SpecVersion.OPENAPI_3_1]:
            components = self.spec.get("components", {})
            schemes = components.get("securitySchemes", {})
        else:
            # Swagger 2.0
            schemes = self.spec.get("securityDefinitions", {})
        
        for name, scheme_def in schemes.items():
            scheme_type = scheme_def.get("type", "")
            
            auth_type = AuthType.NONE
            if scheme_type == "apiKey":
                auth_type = AuthType.API_KEY
            elif scheme_type == "http":
                http_scheme = scheme_def.get("scheme", "").lower()
                if http_scheme == "bearer":
                    auth_type = AuthType.BEARER
                elif http_scheme == "basic":
                    auth_type = AuthType.BASIC
            elif scheme_type == "oauth2":
                auth_type = AuthType.OAUTH2
            elif scheme_type == "openIdConnect":
                auth_type = AuthType.OPENID
            
            self.result.security_schemes.append(SecurityScheme(
                name=name,
                auth_type=auth_type,
                location=scheme_def.get("in"),
                param_name=scheme_def.get("name"),
                scheme=scheme_def.get("scheme"),
                flows=scheme_def.get("flows"),
            ))
    
    def _parse_tags(self):
        """Parse tag definitions."""
        tags = self.spec.get("tags", [])
        for tag in tags:
            name = tag.get("name", "")
            description = tag.get("description", "")
            if name:
                self.result.tags[name] = description
    
    def _parse_paths(self):
        """Parse all paths/endpoints."""
        paths = self.spec.get("paths", {})
        
        for path, path_item in paths.items():
            # Handle path-level parameters
            path_params = path_item.get("parameters", [])
            
            # Parse each HTTP method
            for method in ["get", "post", "put", "patch", "delete", "head", "options", "trace"]:
                if method not in path_item:
                    continue
                
                operation = path_item[method]
                endpoint = self._parse_operation(path, method, operation, path_params)
                self.result.endpoints.append(endpoint)
    
    def _parse_operation(
        self,
        path: str,
        method: str,
        operation: Dict,
        path_params: List[Dict],
    ) -> APIEndpoint:
        """Parse a single operation/endpoint."""
        endpoint = APIEndpoint(
            path=path,
            method=method.upper(),
            operation_id=operation.get("operationId"),
            summary=operation.get("summary", ""),
            description=operation.get("description", ""),
            tags=operation.get("tags", []),
            deprecated=operation.get("deprecated", False),
        )
        
        # Parse parameters (combine path-level and operation-level)
        all_params = path_params + operation.get("parameters", [])
        for param_def in all_params:
            param = self._parse_parameter(param_def)
            if param:
                endpoint.parameters.append(param)
        
        # Parse request body (OpenAPI 3.x)
        if "requestBody" in operation:
            self._parse_request_body(endpoint, operation["requestBody"])
        
        # Parse responses
        for status_code, response_def in operation.get("responses", {}).items():
            description = response_def.get("description", "")
            endpoint.responses[status_code] = description
        
        # Parse security requirements
        security = operation.get("security", self.spec.get("security", []))
        for sec_req in security:
            for scheme_name in sec_req.keys():
                if scheme_name not in endpoint.security:
                    endpoint.security.append(scheme_name)
        
        return endpoint
    
    def _parse_parameter(self, param_def: Dict) -> Optional[APIParameter]:
        """Parse a parameter definition."""
        # Handle $ref
        if "$ref" in param_def:
            param_def = self._resolve_ref(param_def["$ref"])
            if not param_def:
                return None
        
        name = param_def.get("name", "")
        if not name:
            return None
        
        # Determine location
        location_str = param_def.get("in", "query")
        try:
            location = ParameterLocation(location_str)
        except ValueError:
            location = ParameterLocation.QUERY
        
        # Determine type
        schema = param_def.get("schema", param_def)
        type_str = schema.get("type", "string")
        try:
            param_type = ParameterType(type_str)
        except ValueError:
            param_type = ParameterType.STRING
        
        return APIParameter(
            name=name,
            location=location,
            param_type=param_type,
            required=param_def.get("required", False),
            description=param_def.get("description", ""),
            example=param_def.get("example") or schema.get("example"),
            default=schema.get("default"),
            enum=schema.get("enum", []),
            format=schema.get("format"),
            min_length=schema.get("minLength"),
            max_length=schema.get("maxLength"),
            pattern=schema.get("pattern"),
        )
    
    def _parse_request_body(self, endpoint: APIEndpoint, request_body: Dict):
        """Parse request body definition."""
        # Handle $ref
        if "$ref" in request_body:
            request_body = self._resolve_ref(request_body["$ref"])
            if not request_body:
                return
        
        content = request_body.get("content", {})
        
        # Prefer JSON, then form data
        if "application/json" in content:
            endpoint.request_body_type = "application/json"
            schema = content["application/json"].get("schema", {})
            endpoint.request_body_schema = self._resolve_schema(schema)
        
        elif "application/x-www-form-urlencoded" in content:
            endpoint.request_body_type = "application/x-www-form-urlencoded"
            schema = content["application/x-www-form-urlencoded"].get("schema", {})
            endpoint.request_body_schema = self._resolve_schema(schema)
        
        elif "multipart/form-data" in content:
            endpoint.request_body_type = "multipart/form-data"
            schema = content["multipart/form-data"].get("schema", {})
            endpoint.request_body_schema = self._resolve_schema(schema)
        
        elif content:
            # Use first available content type
            content_type = list(content.keys())[0]
            endpoint.request_body_type = content_type
            schema = content[content_type].get("schema", {})
            endpoint.request_body_schema = self._resolve_schema(schema)
    
    def _resolve_ref(self, ref: str) -> Optional[Dict]:
        """Resolve a $ref pointer."""
        if ref in self._resolved_refs:
            return self._resolved_refs[ref]
        
        if not ref.startswith("#/"):
            self.result.warnings.append(f"External $ref not supported: {ref}")
            return None
        
        # Navigate the path
        parts = ref[2:].split("/")
        current = self.spec
        
        for part in parts:
            # Handle JSON pointer escaping
            part = part.replace("~1", "/").replace("~0", "~")
            if isinstance(current, dict) and part in current:
                current = current[part]
            else:
                self.result.warnings.append(f"Could not resolve $ref: {ref}")
                return None
        
        self._resolved_refs[ref] = current
        return current
    
    def _resolve_schema(self, schema: Dict) -> Dict:
        """Resolve all $refs in a schema."""
        if not schema:
            return {}
        
        if "$ref" in schema:
            resolved = self._resolve_ref(schema["$ref"])
            if resolved:
                return self._resolve_schema(resolved)
            return {}
        
        result = dict(schema)
        
        # Resolve nested schemas
        if "properties" in result:
            result["properties"] = {
                k: self._resolve_schema(v)
                for k, v in result["properties"].items()
            }
        
        if "items" in result:
            result["items"] = self._resolve_schema(result["items"])
        
        if "allOf" in result:
            # Merge allOf schemas
            merged = {}
            for sub_schema in result["allOf"]:
                resolved = self._resolve_schema(sub_schema)
                if resolved.get("properties"):
                    if "properties" not in merged:
                        merged["properties"] = {}
                    merged["properties"].update(resolved["properties"])
                merged.update({k: v for k, v in resolved.items() if k != "properties"})
            result = merged
        
        return result


# =============================================================================
# CONVENIENCE FUNCTIONS
# =============================================================================

async def parse_openapi_url(url: str, headers: Optional[Dict[str, str]] = None) -> ParsedAPISpec:
    """Parse an OpenAPI spec from a URL."""
    parser = OpenAPIParser()
    return await parser.parse_url(url, headers)


def parse_openapi_content(content: str, base_url: str = "") -> ParsedAPISpec:
    """Parse an OpenAPI spec from string content."""
    parser = OpenAPIParser()
    return parser.parse_content(content, base_url)


def parse_openapi_file(filepath: str, base_url: str = "") -> ParsedAPISpec:
    """Parse an OpenAPI spec from a file."""
    parser = OpenAPIParser()
    return parser.parse_file(filepath, base_url)


def generate_fuzzing_targets_from_spec(spec: ParsedAPISpec) -> List[Dict[str, Any]]:
    """Generate fuzzing targets from a parsed spec."""
    return spec.generate_fuzzing_targets()


# =============================================================================
# COMMON OPENAPI SPEC ENDPOINTS
# =============================================================================

COMMON_SPEC_PATHS = [
    "/openapi.json",
    "/openapi.yaml",
    "/swagger.json",
    "/swagger.yaml",
    "/api-docs",
    "/api-docs.json",
    "/api/swagger.json",
    "/api/openapi.json",
    "/v1/swagger.json",
    "/v2/swagger.json",
    "/v3/swagger.json",
    "/api/v1/swagger.json",
    "/api/v2/swagger.json",
    "/api/v3/swagger.json",
    "/docs/swagger.json",
    "/swagger/v1/swagger.json",
    "/.well-known/openapi.json",
]


async def discover_openapi_spec(base_url: str, headers: Optional[Dict[str, str]] = None, verify_ssl: bool = True) -> Optional[str]:
    """Try to discover an OpenAPI spec at common paths.

    Args:
        base_url: Base URL to search for OpenAPI spec
        headers: Optional HTTP headers
        verify_ssl: Whether to verify SSL certificates (default True)
    """
    async with httpx.AsyncClient(timeout=10.0, verify=verify_ssl) as client:
        for path in COMMON_SPEC_PATHS:
            try:
                url = urljoin(base_url.rstrip("/") + "/", path.lstrip("/"))
                response = await client.get(url, headers=headers or {})
                
                if response.status_code == 200:
                    content = response.text
                    # Quick validation
                    if "openapi" in content.lower() or "swagger" in content.lower():
                        return url
            except Exception:
                continue
    
    return None
