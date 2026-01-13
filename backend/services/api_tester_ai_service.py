"""
API Tester AI Service

AI-powered features for the API tester:
- Natural Language to API Request conversion
- AI Test/Assertion Generator
- Smart Variable Detection
- Response Anomaly Detection
- API Documentation Generator
"""

import json
import logging
import re
from typing import Any, Dict, List, Optional, Tuple
from dataclasses import dataclass, field

from backend.services.ai_analysis_service import get_ai_response

logger = logging.getLogger(__name__)


# =============================================================================
# Data Transfer Objects
# =============================================================================

@dataclass
class GeneratedRequest:
    """Generated API request from natural language."""
    method: str = "GET"
    url: str = ""
    headers: Dict[str, str] = field(default_factory=dict)
    body: Optional[str] = None
    body_type: str = "none"  # none, json, form, raw
    description: str = ""
    confidence: float = 0.0
    suggestions: List[str] = field(default_factory=list)


@dataclass
class GeneratedTest:
    """Generated test assertion."""
    name: str = ""
    type: str = "status"  # status, json_path, header, response_time, contains
    target: str = ""  # JSON path, header name, etc.
    operator: str = "equals"  # equals, not_equals, contains, greater_than, less_than, exists, matches
    expected: Any = None
    code: str = ""  # JavaScript test code
    description: str = ""


@dataclass
class SuggestedVariable:
    """Suggested variable to extract from response."""
    name: str = ""
    json_path: str = ""
    sample_value: Any = None
    description: str = ""
    scope: str = "environment"  # environment, collection, global


@dataclass
class ResponseAnomaly:
    """Detected anomaly in response."""
    type: str = ""  # security, performance, data, schema
    severity: str = "info"  # info, warning, error
    title: str = ""
    description: str = ""
    location: Optional[str] = None
    suggestion: Optional[str] = None


# =============================================================================
# Natural Language to API Request
# =============================================================================

async def natural_language_to_request(
    query: str,
    context: Optional[Dict[str, Any]] = None,
) -> GeneratedRequest:
    """
    Convert natural language description to an API request.
    
    Args:
        query: Natural language description like "Get all users with admin role"
        context: Optional context like base_url, available_endpoints, auth_info
    
    Returns:
        GeneratedRequest with method, url, headers, body
    """
    try:
        context_info = ""
        if context:
            if context.get("base_url"):
                context_info += f"\nBase URL: {context['base_url']}"
            if context.get("available_endpoints"):
                context_info += f"\nAvailable endpoints: {json.dumps(context['available_endpoints'][:10])}"
            if context.get("auth_type"):
                context_info += f"\nAuthentication: {context['auth_type']}"
            if context.get("variables"):
                context_info += f"\nAvailable variables: {list(context['variables'].keys())}"
        
        prompt = f"""You are an API request generator. Convert the following natural language description into an API request.

User Request: "{query}"
{context_info}

Respond with a JSON object containing:
{{
    "method": "GET|POST|PUT|PATCH|DELETE",
    "url": "/api/endpoint/path",
    "headers": {{"Content-Type": "application/json", ...}},
    "body": null or JSON object/string,
    "body_type": "none|json|form|raw",
    "description": "Brief description of what this request does",
    "confidence": 0.0-1.0,
    "suggestions": ["Alternative approaches or improvements"]
}}

Rules:
- Use RESTful conventions
- Include appropriate Content-Type headers
- Use {{{{variable}}}} syntax for dynamic values
- If the request is ambiguous, provide your best interpretation with lower confidence
- Include helpful suggestions for the user

Respond ONLY with the JSON object, no explanation."""

        response = await get_ai_response(prompt, max_tokens=1000)
        
        # Parse JSON from response
        json_match = re.search(r'\{[\s\S]*\}', response)
        if json_match:
            data = json.loads(json_match.group())
            return GeneratedRequest(
                method=data.get("method", "GET").upper(),
                url=data.get("url", ""),
                headers=data.get("headers", {}),
                body=json.dumps(data["body"]) if data.get("body") else None,
                body_type=data.get("body_type", "none"),
                description=data.get("description", ""),
                confidence=float(data.get("confidence", 0.5)),
                suggestions=data.get("suggestions", []),
            )
        
        # Fallback: simple pattern matching
        return _fallback_request_parser(query)
        
    except Exception as e:
        logger.error(f"Failed to generate request from NL: {e}")
        return _fallback_request_parser(query)


def _fallback_request_parser(query: str) -> GeneratedRequest:
    """Simple pattern-based fallback parser."""
    query_lower = query.lower()
    
    method = "GET"
    if any(w in query_lower for w in ["create", "add", "post", "submit", "send"]):
        method = "POST"
    elif any(w in query_lower for w in ["update", "edit", "modify", "change"]):
        method = "PUT"
    elif any(w in query_lower for w in ["delete", "remove", "destroy"]):
        method = "DELETE"
    elif any(w in query_lower for w in ["patch", "partial"]):
        method = "PATCH"
    
    # Extract potential resource names
    resources = re.findall(r'\b(users?|products?|items?|orders?|posts?|comments?|articles?|categories?|tags?)\b', query_lower)
    url = f"/api/{resources[0]}" if resources else "/api/resource"
    
    # Check for ID references
    if any(w in query_lower for w in ["by id", "with id", "specific", "single"]):
        url += "/{{id}}"
    
    return GeneratedRequest(
        method=method,
        url=url,
        headers={"Content-Type": "application/json"} if method in ["POST", "PUT", "PATCH"] else {},
        body='{"key": "value"}' if method in ["POST", "PUT", "PATCH"] else None,
        body_type="json" if method in ["POST", "PUT", "PATCH"] else "none",
        description=f"Generated from: {query}",
        confidence=0.3,
        suggestions=["Consider adding more specific endpoint path", "Review generated request before sending"],
    )


# =============================================================================
# AI Test Generator
# =============================================================================

async def generate_tests_from_response(
    request: Dict[str, Any],
    response: Dict[str, Any],
    test_types: Optional[List[str]] = None,
) -> List[GeneratedTest]:
    """
    Generate test assertions based on request/response.
    
    Args:
        request: The API request (method, url, headers, body)
        response: The API response (status, headers, body, time)
        test_types: Optional list of test types to generate
    
    Returns:
        List of GeneratedTest objects
    """
    try:
        # Truncate response body if too large
        response_body = response.get("body", "")
        if isinstance(response_body, str) and len(response_body) > 5000:
            response_body = response_body[:5000] + "... [truncated]"
        
        prompt = f"""You are a test generator for API endpoints. Generate comprehensive test assertions based on this request/response.

REQUEST:
- Method: {request.get('method', 'GET')}
- URL: {request.get('url', '')}
- Headers: {json.dumps(request.get('headers', {}))}
- Body: {request.get('body', 'null')}

RESPONSE:
- Status: {response.get('status_code', 200)} {response.get('status_text', 'OK')}
- Response Time: {response.get('response_time_ms', 0)}ms
- Headers: {json.dumps(response.get('headers', {}))}
- Body: {response_body}

Generate a JSON array of test assertions. Each test should have:
{{
    "name": "Human-readable test name",
    "type": "status|json_path|header|response_time|contains|schema",
    "target": "JSON path or header name (e.g., $.data.id, Content-Type)",
    "operator": "equals|not_equals|contains|greater_than|less_than|exists|matches|is_type",
    "expected": "expected value",
    "code": "JavaScript test code using pm.test() and pm.expect()",
    "description": "What this test verifies"
}}

Generate 5-10 meaningful tests covering:
1. Status code verification
2. Response time check
3. Content-Type header
4. Key data structure validation
5. Business logic assertions
6. Security-related checks (if applicable)

Respond ONLY with the JSON array."""

        response_text = await get_ai_response(prompt, max_tokens=2000)
        
        # Parse JSON array
        json_match = re.search(r'\[[\s\S]*\]', response_text)
        if json_match:
            tests_data = json.loads(json_match.group())
            tests = []
            for t in tests_data:
                tests.append(GeneratedTest(
                    name=t.get("name", "Test"),
                    type=t.get("type", "status"),
                    target=t.get("target", ""),
                    operator=t.get("operator", "equals"),
                    expected=t.get("expected"),
                    code=t.get("code", ""),
                    description=t.get("description", ""),
                ))
            return tests
        
        return _generate_basic_tests(response)
        
    except Exception as e:
        logger.error(f"Failed to generate tests: {e}")
        return _generate_basic_tests(response)


def _generate_basic_tests(response: Dict[str, Any]) -> List[GeneratedTest]:
    """Generate basic tests without AI."""
    tests = []
    
    status = response.get("status_code", 200)
    tests.append(GeneratedTest(
        name=f"Status code is {status}",
        type="status",
        target="status_code",
        operator="equals",
        expected=status,
        code=f'pm.test("Status code is {status}", function () {{\n    pm.response.to.have.status({status});\n}});',
        description="Verify the response status code",
    ))
    
    # Response time test
    tests.append(GeneratedTest(
        name="Response time is acceptable",
        type="response_time",
        target="response_time",
        operator="less_than",
        expected=2000,
        code='pm.test("Response time is less than 2000ms", function () {\n    pm.expect(pm.response.responseTime).to.be.below(2000);\n});',
        description="Verify response time is under 2 seconds",
    ))
    
    # Content-Type test
    content_type = response.get("headers", {}).get("Content-Type", response.get("headers", {}).get("content-type", ""))
    if content_type:
        tests.append(GeneratedTest(
            name="Content-Type header is present",
            type="header",
            target="Content-Type",
            operator="contains",
            expected="application/json" if "json" in content_type else content_type.split(";")[0],
            code=f'pm.test("Content-Type is correct", function () {{\n    pm.response.to.have.header("Content-Type");\n}});',
            description="Verify Content-Type header",
        ))
    
    # JSON structure test
    body = response.get("body", "")
    if body and isinstance(body, str):
        try:
            json_body = json.loads(body)
            if isinstance(json_body, dict):
                keys = list(json_body.keys())[:3]
                for key in keys:
                    tests.append(GeneratedTest(
                        name=f"Response has '{key}' property",
                        type="json_path",
                        target=f"$.{key}",
                        operator="exists",
                        expected=True,
                        code=f'pm.test("Response has {key}", function () {{\n    var jsonData = pm.response.json();\n    pm.expect(jsonData).to.have.property("{key}");\n}});',
                        description=f"Verify '{key}' exists in response",
                    ))
        except:
            pass
    
    return tests


# =============================================================================
# Smart Variable Detection
# =============================================================================

async def suggest_variables_from_response(
    response_body: str,
    request_context: Optional[Dict[str, Any]] = None,
) -> List[SuggestedVariable]:
    """
    Analyze response and suggest variables to extract.
    
    Args:
        response_body: JSON response body
        request_context: Optional context about the request
    
    Returns:
        List of SuggestedVariable suggestions
    """
    try:
        # Truncate if too large
        if len(response_body) > 5000:
            response_body = response_body[:5000] + "... [truncated]"
        
        prompt = f"""Analyze this API response and suggest variables that would be useful to extract for use in subsequent requests.

RESPONSE BODY:
{response_body}

{f"REQUEST CONTEXT: {json.dumps(request_context)}" if request_context else ""}

Identify values that are likely to be:
1. IDs (user_id, order_id, etc.) - useful for subsequent requests
2. Tokens (auth tokens, CSRF tokens, session IDs)
3. URLs (for pagination, related resources)
4. Timestamps (for filtering, versioning)
5. Counts/totals (for assertions, pagination)

Return a JSON array with suggested variables:
[
    {{
        "name": "suggested_variable_name",
        "json_path": "$.path.to.value",
        "sample_value": "actual value from response",
        "description": "Why this variable is useful",
        "scope": "environment|collection|global"
    }}
]

Suggest 3-8 most useful variables. Use camelCase for names.
Respond ONLY with the JSON array."""

        response_text = await get_ai_response(prompt, max_tokens=1500)
        
        # Parse JSON array
        json_match = re.search(r'\[[\s\S]*\]', response_text)
        if json_match:
            vars_data = json.loads(json_match.group())
            variables = []
            for v in vars_data:
                variables.append(SuggestedVariable(
                    name=v.get("name", "variable"),
                    json_path=v.get("json_path", "$"),
                    sample_value=v.get("sample_value"),
                    description=v.get("description", ""),
                    scope=v.get("scope", "environment"),
                ))
            return variables
        
        return _detect_variables_simple(response_body)
        
    except Exception as e:
        logger.error(f"Failed to suggest variables: {e}")
        return _detect_variables_simple(response_body)


def _detect_variables_simple(response_body: str) -> List[SuggestedVariable]:
    """Simple variable detection without AI."""
    variables = []
    
    try:
        data = json.loads(response_body)
        
        def extract_vars(obj: Any, path: str = "$"):
            if isinstance(obj, dict):
                for key, value in obj.items():
                    current_path = f"{path}.{key}"
                    
                    # Detect IDs
                    if key.lower().endswith("id") or key.lower() == "id":
                        variables.append(SuggestedVariable(
                            name=_to_camel_case(key),
                            json_path=current_path,
                            sample_value=value,
                            description=f"ID field - useful for subsequent requests",
                            scope="environment",
                        ))
                    
                    # Detect tokens
                    elif "token" in key.lower() or key.lower() in ["access_token", "refresh_token", "jwt", "bearer"]:
                        variables.append(SuggestedVariable(
                            name=_to_camel_case(key),
                            json_path=current_path,
                            sample_value=str(value)[:50] + "..." if len(str(value)) > 50 else value,
                            description=f"Authentication token",
                            scope="environment",
                        ))
                    
                    # Detect URLs
                    elif isinstance(value, str) and (value.startswith("http") or key.lower() in ["url", "href", "link", "next", "previous"]):
                        variables.append(SuggestedVariable(
                            name=_to_camel_case(key),
                            json_path=current_path,
                            sample_value=value,
                            description=f"URL for navigation or related resource",
                            scope="collection",
                        ))
                    
                    # Recurse into nested objects (limit depth)
                    if path.count(".") < 3:
                        extract_vars(value, current_path)
            
            elif isinstance(obj, list) and len(obj) > 0:
                extract_vars(obj[0], f"{path}[0]")
        
        extract_vars(data)
        
    except:
        pass
    
    return variables[:8]  # Limit to 8 suggestions


def _to_camel_case(name: str) -> str:
    """Convert string to camelCase."""
    parts = re.split(r'[-_\s]', name)
    return parts[0].lower() + ''.join(p.capitalize() for p in parts[1:])


# =============================================================================
# Response Anomaly Detection
# =============================================================================

async def detect_response_anomalies(
    request: Dict[str, Any],
    response: Dict[str, Any],
    history: Optional[List[Dict[str, Any]]] = None,
) -> List[ResponseAnomaly]:
    """
    Detect anomalies in API response.
    
    Args:
        request: The API request
        response: The API response
        history: Optional historical responses for comparison
    
    Returns:
        List of detected anomalies
    """
    anomalies = []
    
    # Quick checks without AI
    anomalies.extend(_check_security_anomalies(response))
    anomalies.extend(_check_performance_anomalies(response))
    anomalies.extend(_check_data_anomalies(response))
    
    # AI-powered deep analysis if there's complex data
    if response.get("body") and len(response.get("body", "")) > 100:
        try:
            ai_anomalies = await _ai_analyze_anomalies(request, response, history)
            anomalies.extend(ai_anomalies)
        except Exception as e:
            logger.warning(f"AI anomaly detection failed: {e}")
    
    return anomalies


def _check_security_anomalies(response: Dict[str, Any]) -> List[ResponseAnomaly]:
    """Check for security-related anomalies."""
    anomalies = []
    headers = response.get("headers", {})
    body = response.get("body", "")
    
    # Missing security headers
    security_headers = {
        "X-Content-Type-Options": "nosniff",
        "X-Frame-Options": "DENY or SAMEORIGIN",
        "X-XSS-Protection": "1; mode=block",
        "Strict-Transport-Security": "max-age=...",
        "Content-Security-Policy": "policy",
    }
    
    for header, expected in security_headers.items():
        if header.lower() not in [h.lower() for h in headers.keys()]:
            anomalies.append(ResponseAnomaly(
                type="security",
                severity="warning",
                title=f"Missing {header} header",
                description=f"The {header} security header is not present in the response.",
                suggestion=f"Consider adding: {header}: {expected}",
            ))
    
    # Sensitive data exposure
    sensitive_patterns = [
        (r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b', "email address"),
        (r'\b(?:\d{4}[-\s]?){3}\d{4}\b', "credit card number"),
        (r'\b\d{3}-\d{2}-\d{4}\b', "SSN"),
        (r'(?i)(password|passwd|pwd)\s*["\']?\s*[:=]\s*["\']?[^"\'}\s]+', "password field"),
        (r'(?i)(api[_-]?key|apikey|secret[_-]?key)\s*["\']?\s*[:=]\s*["\']?[A-Za-z0-9_-]{20,}', "API key"),
        (r'(?i)bearer\s+[A-Za-z0-9_-]{20,}', "bearer token"),
    ]
    
    for pattern, data_type in sensitive_patterns:
        if re.search(pattern, body):
            anomalies.append(ResponseAnomaly(
                type="security",
                severity="error",
                title=f"Potential {data_type} exposure",
                description=f"The response may contain sensitive data ({data_type}).",
                suggestion="Review the response and ensure sensitive data is properly masked or excluded.",
            ))
    
    # Verbose error messages
    error_patterns = [
        (r'(?i)stack\s*trace', "stack trace"),
        (r'(?i)exception\s+in', "exception details"),
        (r'(?i)(mysql|postgresql|oracle|sqlite|mongodb)\s+error', "database error"),
        (r'(?i)syntax\s+error', "syntax error"),
        (r'(?i)at\s+\w+\.\w+\([^)]+:\d+\)', "file path exposure"),
    ]
    
    for pattern, error_type in error_patterns:
        if re.search(pattern, body):
            anomalies.append(ResponseAnomaly(
                type="security",
                severity="warning",
                title=f"Verbose error: {error_type}",
                description=f"The response contains detailed error information ({error_type}) that could help attackers.",
                suggestion="Configure error handling to return generic error messages in production.",
            ))
    
    return anomalies


def _check_performance_anomalies(response: Dict[str, Any]) -> List[ResponseAnomaly]:
    """Check for performance-related anomalies."""
    anomalies = []
    
    response_time = response.get("response_time_ms", 0)
    response_size = response.get("response_size_bytes", 0)
    
    # Slow response
    if response_time > 3000:
        anomalies.append(ResponseAnomaly(
            type="performance",
            severity="warning",
            title="Slow response time",
            description=f"Response took {response_time}ms, which exceeds 3 seconds.",
            suggestion="Consider optimizing the endpoint, adding caching, or pagination.",
        ))
    elif response_time > 1000:
        anomalies.append(ResponseAnomaly(
            type="performance",
            severity="info",
            title="Response time could be improved",
            description=f"Response took {response_time}ms.",
            suggestion="Consider if this endpoint could benefit from optimization.",
        ))
    
    # Large response
    if response_size > 1_000_000:  # 1MB
        anomalies.append(ResponseAnomaly(
            type="performance",
            severity="warning",
            title="Large response size",
            description=f"Response is {response_size / 1024 / 1024:.2f}MB.",
            suggestion="Consider implementing pagination, filtering, or compression.",
        ))
    elif response_size > 100_000:  # 100KB
        anomalies.append(ResponseAnomaly(
            type="performance",
            severity="info",
            title="Response size is notable",
            description=f"Response is {response_size / 1024:.1f}KB.",
            suggestion="For mobile clients, consider offering a lighter endpoint.",
        ))
    
    # No caching headers
    headers = response.get("headers", {})
    cache_headers = ["cache-control", "etag", "last-modified", "expires"]
    if not any(h.lower() in [hh.lower() for hh in headers.keys()] for h in cache_headers):
        anomalies.append(ResponseAnomaly(
            type="performance",
            severity="info",
            title="No caching headers",
            description="Response doesn't include caching headers.",
            suggestion="Consider adding Cache-Control, ETag, or Last-Modified headers for cacheable responses.",
        ))
    
    return anomalies


def _check_data_anomalies(response: Dict[str, Any]) -> List[ResponseAnomaly]:
    """Check for data-related anomalies."""
    anomalies = []
    body = response.get("body", "")
    status = response.get("status_code", 200)
    
    # Empty response for success status
    if status in [200, 201] and (not body or body.strip() in ["", "{}", "[]", "null"]):
        anomalies.append(ResponseAnomaly(
            type="data",
            severity="info",
            title="Empty response body",
            description=f"Status {status} returned with empty or minimal body.",
            suggestion="Consider if this is intentional or if data should be returned.",
        ))
    
    # Check JSON structure
    if body:
        try:
            data = json.loads(body)
            
            # Null values
            null_count = _count_nulls(data)
            if null_count > 5:
                anomalies.append(ResponseAnomaly(
                    type="data",
                    severity="info",
                    title="Multiple null values",
                    description=f"Response contains {null_count} null values.",
                    suggestion="Verify if null values are expected or indicate missing data.",
                ))
            
            # Inconsistent array items
            if isinstance(data, list) and len(data) > 1:
                keys_set = [set(item.keys()) if isinstance(item, dict) else set() for item in data[:10]]
                if len(set(frozenset(k) for k in keys_set)) > 1:
                    anomalies.append(ResponseAnomaly(
                        type="data",
                        severity="warning",
                        title="Inconsistent array structure",
                        description="Array items have different keys/properties.",
                        suggestion="Ensure array items have consistent structure for easier client handling.",
                    ))
            
        except json.JSONDecodeError:
            if "application/json" in response.get("headers", {}).get("Content-Type", ""):
                anomalies.append(ResponseAnomaly(
                    type="data",
                    severity="error",
                    title="Invalid JSON response",
                    description="Content-Type indicates JSON but body is not valid JSON.",
                    suggestion="Check server response formatting.",
                ))
    
    return anomalies


def _count_nulls(obj: Any, count: int = 0) -> int:
    """Count null values in a JSON structure."""
    if obj is None:
        return count + 1
    if isinstance(obj, dict):
        for v in obj.values():
            count = _count_nulls(v, count)
    elif isinstance(obj, list):
        for item in obj[:20]:  # Limit iteration
            count = _count_nulls(item, count)
    return count


async def _ai_analyze_anomalies(
    request: Dict[str, Any],
    response: Dict[str, Any],
    history: Optional[List[Dict[str, Any]]] = None,
) -> List[ResponseAnomaly]:
    """AI-powered deep anomaly analysis."""
    try:
        body = response.get("body", "")
        if len(body) > 3000:
            body = body[:3000] + "... [truncated]"
        
        history_context = ""
        if history and len(history) > 0:
            history_context = f"\nPrevious responses for comparison: {json.dumps(history[:3])}"
        
        prompt = f"""Analyze this API response for anomalies, issues, or areas of concern.

REQUEST: {request.get('method')} {request.get('url')}
STATUS: {response.get('status_code')} {response.get('status_text')}
RESPONSE TIME: {response.get('response_time_ms')}ms
RESPONSE BODY:
{body}
{history_context}

Look for:
1. Data inconsistencies or unexpected values
2. Schema issues (wrong types, missing required fields)
3. Business logic concerns
4. API design anti-patterns
5. Potential security issues not caught by pattern matching

Return a JSON array of anomalies found (or empty array if none):
[
    {{
        "type": "security|performance|data|schema|design",
        "severity": "info|warning|error",
        "title": "Brief issue title",
        "description": "Detailed description",
        "location": "path or field if applicable",
        "suggestion": "How to fix or improve"
    }}
]

Only report meaningful issues, not minor style preferences. Respond ONLY with JSON array."""

        response_text = await get_ai_response(prompt, max_tokens=1500)
        
        json_match = re.search(r'\[[\s\S]*\]', response_text)
        if json_match:
            anomalies_data = json.loads(json_match.group())
            return [
                ResponseAnomaly(
                    type=a.get("type", "data"),
                    severity=a.get("severity", "info"),
                    title=a.get("title", ""),
                    description=a.get("description", ""),
                    location=a.get("location"),
                    suggestion=a.get("suggestion"),
                )
                for a in anomalies_data
            ]
        
        return []
        
    except Exception as e:
        logger.warning(f"AI anomaly analysis failed: {e}")
        return []


# =============================================================================
# API Documentation Generator
# =============================================================================

async def generate_endpoint_documentation(
    request: Dict[str, Any],
    response: Dict[str, Any],
) -> Dict[str, Any]:
    """
    Generate documentation for an API endpoint based on request/response.
    
    Returns a structured documentation object.
    """
    try:
        body = response.get("body", "")
        if len(body) > 3000:
            body = body[:3000] + "... [truncated]"
        
        prompt = f"""Generate API documentation for this endpoint based on the request/response.

REQUEST:
- Method: {request.get('method')}
- URL: {request.get('url')}
- Headers: {json.dumps(request.get('headers', {}))}
- Body: {request.get('body', 'null')}

RESPONSE:
- Status: {response.get('status_code')} {response.get('status_text')}
- Body: {body}

Generate documentation in this JSON format:
{{
    "summary": "Brief one-line description",
    "description": "Detailed description of what this endpoint does",
    "parameters": [
        {{"name": "param", "in": "query|path|header", "type": "string", "required": true, "description": "..."}}
    ],
    "request_body": {{
        "content_type": "application/json",
        "schema": {{}},
        "example": {{}}
    }},
    "responses": {{
        "200": {{
            "description": "Success response description",
            "schema": {{}},
            "example": {{}}
        }}
    }},
    "tags": ["category"],
    "security": ["bearer"],
    "examples": [
        {{"title": "Example name", "request": {{}}, "response": {{}}}}
    ]
}}

Respond ONLY with the JSON documentation."""

        response_text = await get_ai_response(prompt, max_tokens=2000)
        
        json_match = re.search(r'\{[\s\S]*\}', response_text)
        if json_match:
            return json.loads(json_match.group())
        
        return _generate_basic_documentation(request, response)
        
    except Exception as e:
        logger.error(f"Failed to generate documentation: {e}")
        return _generate_basic_documentation(request, response)


def _generate_basic_documentation(request: Dict[str, Any], response: Dict[str, Any]) -> Dict[str, Any]:
    """Generate basic documentation without AI."""
    return {
        "summary": f"{request.get('method')} {request.get('url')}",
        "description": "Auto-generated documentation",
        "parameters": [],
        "request_body": {
            "content_type": "application/json",
            "example": request.get("body"),
        } if request.get("body") else None,
        "responses": {
            str(response.get("status_code", 200)): {
                "description": response.get("status_text", "OK"),
                "example": response.get("body"),
            }
        },
        "tags": [],
    }
