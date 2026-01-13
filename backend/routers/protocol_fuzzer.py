"""
GraphQL and WebSocket Fuzzing Router

API endpoints for GraphQL and WebSocket security testing.
"""

from fastapi import APIRouter, HTTPException, Depends
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, Field
from typing import Any, Dict, List, Optional
import json
import logging
import asyncio

from backend.core.auth import get_current_active_user
from backend.models.models import User

from backend.services.graphql_websocket_fuzzer import (
    GraphQLFuzzer,
    WebSocketFuzzer,
    scan_graphql_endpoint,
    scan_websocket_endpoint,
    is_graphql_endpoint,
    is_websocket_endpoint,
    GraphQLAttackType,
    WebSocketAttackType,
    WEBSOCKETS_AVAILABLE,
)

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/protocol-fuzzer", tags=["Protocol Fuzzer"])


# =============================================================================
# REQUEST MODELS
# =============================================================================

class GraphQLScanRequest(BaseModel):
    """Request to scan a GraphQL endpoint."""
    endpoint: str = Field(..., description="GraphQL endpoint URL")
    headers: Dict[str, str] = Field(default_factory=dict, description="HTTP headers")
    timeout: float = Field(default=30.0, ge=5, le=120, description="Request timeout in seconds")
    techniques: List[str] = Field(
        default_factory=list,
        description="Specific techniques to test (empty = all)"
    )


class WebSocketScanRequest(BaseModel):
    """Request to scan a WebSocket endpoint."""
    endpoint: str = Field(..., description="WebSocket endpoint URL (ws:// or wss://)")
    headers: Dict[str, str] = Field(default_factory=dict, description="HTTP headers")
    subprotocols: List[str] = Field(default_factory=list, description="WebSocket subprotocols")
    timeout: float = Field(default=30.0, ge=5, le=120, description="Connection timeout in seconds")
    techniques: List[str] = Field(
        default_factory=list,
        description="Specific techniques to test (empty = all)"
    )


class GraphQLQueryRequest(BaseModel):
    """Request to send a custom GraphQL query."""
    endpoint: str = Field(..., description="GraphQL endpoint URL")
    query: str = Field(..., description="GraphQL query to send")
    variables: Dict[str, Any] = Field(default_factory=dict, description="Query variables")
    headers: Dict[str, str] = Field(default_factory=dict, description="HTTP headers")


class WebSocketMessageRequest(BaseModel):
    """Request to send a custom WebSocket message."""
    endpoint: str = Field(..., description="WebSocket endpoint URL")
    messages: List[str] = Field(..., description="Messages to send")
    headers: Dict[str, str] = Field(default_factory=dict, description="HTTP headers")
    wait_for_response: bool = Field(default=True, description="Wait for responses")


class WebSocketDeepScanRequest(BaseModel):
    """Request for deep WebSocket scanning."""
    endpoint: str = Field(..., description="WebSocket endpoint URL (ws:// or wss://)")
    headers: Dict[str, str] = Field(default_factory=dict, description="HTTP headers")
    subprotocols: List[str] = Field(default_factory=list, description="WebSocket subprotocols")
    timeout: float = Field(default=30.0, ge=5, le=120, description="Connection timeout in seconds")
    phases: List[str] = Field(
        default_factory=list,
        description="Specific phases to run (empty = all)"
    )
    custom_sequences: List[List[Dict[str, Any]]] = Field(
        default_factory=list,
        description="Custom message sequences to test"
    )


# =============================================================================
# GRAPHQL ENDPOINTS
# =============================================================================

@router.post("/graphql/scan")
async def scan_graphql(
    request: GraphQLScanRequest,
    current_user: User = Depends(get_current_active_user)
):
    """
    Start a comprehensive GraphQL security scan.
    
    Tests for:
    - Introspection exposure
    - SQL/NoSQL injection in variables
    - XSS in variables
    - SSRF vulnerabilities
    - Query depth attacks (DoS)
    - Batch query attacks
    - Field enumeration
    - Authentication bypass
    - IDOR vulnerabilities
    
    Returns a streaming response with scan events.
    """
    async def generate():
        try:
            async for event in scan_graphql_endpoint(
                endpoint=request.endpoint,
                headers=request.headers,
                timeout=request.timeout,
            ):
                yield f"data: {json.dumps(event)}\n\n"
        except Exception as e:
            yield f"data: {json.dumps({'type': 'error', 'error': str(e)})}\n\n"
    
    return StreamingResponse(
        generate(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",
        }
    )


@router.post("/graphql/introspect")
async def introspect_graphql(
    request: GraphQLScanRequest,
    current_user: User = Depends(get_current_active_user)
):
    """
    Perform GraphQL introspection only.
    
    Returns the discovered schema if introspection is enabled.
    """
    fuzzer = GraphQLFuzzer(
        endpoint=request.endpoint,
        headers=request.headers,
        timeout=request.timeout,
    )
    
    results = []
    schema = None
    
    try:
        async for event in fuzzer.introspect():
            results.append(event)
            if event.get("type") == "schema_discovered":
                schema = event.get("schema")
    finally:
        await fuzzer.close()
    
    return {
        "endpoint": request.endpoint,
        "introspection_enabled": fuzzer.session.introspection_enabled,
        "schema": schema,
        "events": results,
    }


@router.post("/graphql/query")
async def send_graphql_query(
    request: GraphQLQueryRequest,
    current_user: User = Depends(get_current_active_user)
):
    """
    Send a custom GraphQL query for manual testing.
    """
    import httpx
    
    headers = {"Content-Type": "application/json", **request.headers}
    body = {"query": request.query}
    if request.variables:
        body["variables"] = request.variables
    
    try:
        async with httpx.AsyncClient(timeout=30.0, verify=False) as client:
            response = await client.post(
                request.endpoint,
                json=body,
                headers=headers,
            )
            
            return {
                "status_code": response.status_code,
                "headers": dict(response.headers),
                "body": response.text,
                "json": response.json() if response.headers.get("content-type", "").startswith("application/json") else None,
            }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/graphql/techniques")
async def list_graphql_techniques(
    current_user: User = Depends(get_current_active_user)
):
    """
    List available GraphQL attack techniques.
    """
    return {
        "techniques": [
            {
                "id": t.value,
                "name": t.name.replace("_", " ").title(),
                "description": _get_technique_description(t),
            }
            for t in GraphQLAttackType
        ]
    }


def _get_technique_description(technique: GraphQLAttackType) -> str:
    """Get description for a GraphQL attack technique."""
    descriptions = {
        GraphQLAttackType.INTROSPECTION: "Test if schema introspection is enabled, exposing API structure",
        GraphQLAttackType.INJECTION: "Test for SQL/NoSQL/Command injection in GraphQL variables",
        GraphQLAttackType.DEPTH_ATTACK: "Test query depth limits to detect DoS vulnerabilities",
        GraphQLAttackType.BATCH_ATTACK: "Test batch query limits to detect resource exhaustion",
        GraphQLAttackType.FIELD_SUGGESTION: "Enumerate hidden fields using error suggestions",
        GraphQLAttackType.ALIAS_OVERLOAD: "Test alias limits to detect DoS vulnerabilities",
        GraphQLAttackType.DIRECTIVE_OVERLOAD: "Test directive abuse possibilities",
        GraphQLAttackType.CIRCULAR_FRAGMENT: "Test for circular fragment vulnerabilities",
        GraphQLAttackType.DOS_COMPLEXITY: "Test query complexity limits",
        GraphQLAttackType.AUTH_BYPASS: "Test authentication bypass scenarios",
        GraphQLAttackType.IDOR: "Test for Insecure Direct Object Reference",
    }
    return descriptions.get(technique, "No description available")


# =============================================================================
# WEBSOCKET ENDPOINTS
# =============================================================================

@router.post("/websocket/scan")
async def scan_websocket(
    request: WebSocketScanRequest,
    current_user: User = Depends(get_current_active_user)
):
    """
    Start a comprehensive WebSocket security scan.
    
    Tests for:
    - Message injection (SQLi, XSS, command injection)
    - Authentication bypass
    - Cross-Site WebSocket Hijacking (CSWSH)
    - Race conditions
    - Protocol confusion
    - IDOR via WebSocket channels
    
    Returns a streaming response with scan events.
    """
    if not WEBSOCKETS_AVAILABLE:
        raise HTTPException(
            status_code=501,
            detail="WebSocket scanning not available. Install websockets package."
        )
    
    async def generate():
        try:
            async for event in scan_websocket_endpoint(
                endpoint=request.endpoint,
                headers=request.headers,
                subprotocols=request.subprotocols if request.subprotocols else None,
                timeout=request.timeout,
            ):
                yield f"data: {json.dumps(event)}\n\n"
        except Exception as e:
            yield f"data: {json.dumps({'type': 'error', 'error': str(e)})}\n\n"
    
    return StreamingResponse(
        generate(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",
        }
    )


@router.post("/websocket/connect-test")
async def test_websocket_connection(
    request: WebSocketScanRequest,
    current_user: User = Depends(get_current_active_user)
):
    """
    Test WebSocket connection establishment only.
    """
    if not WEBSOCKETS_AVAILABLE:
        raise HTTPException(
            status_code=501,
            detail="WebSocket testing not available. Install websockets package."
        )
    
    fuzzer = WebSocketFuzzer(
        endpoint=request.endpoint,
        headers=request.headers,
        subprotocols=request.subprotocols if request.subprotocols else None,
        timeout=request.timeout,
    )
    
    results = []
    try:
        async for event in fuzzer.test_connection():
            results.append(event)
    except Exception as e:
        results.append({"type": "error", "error": str(e)})
    
    return {
        "endpoint": request.endpoint,
        "connection_established": fuzzer.session.connection_established,
        "protocols_discovered": fuzzer.session.protocols_discovered,
        "events": results,
    }


@router.post("/websocket/send")
async def send_websocket_messages(
    request: WebSocketMessageRequest,
    current_user: User = Depends(get_current_active_user)
):
    """
    Send custom WebSocket messages for manual testing.
    """
    if not WEBSOCKETS_AVAILABLE:
        raise HTTPException(
            status_code=501,
            detail="WebSocket testing not available. Install websockets package."
        )
    
    import websockets
    
    responses = []
    
    try:
        async with websockets.connect(
            request.endpoint,
            extra_headers=request.headers,
            ping_interval=None,
        ) as ws:
            for msg in request.messages:
                await ws.send(msg)
                
                if request.wait_for_response:
                    try:
                        response = await asyncio.wait_for(ws.recv(), timeout=5.0)
                        responses.append({
                            "sent": msg,
                            "received": response,
                        })
                    except asyncio.TimeoutError:
                        responses.append({
                            "sent": msg,
                            "received": None,
                            "error": "timeout",
                        })
                else:
                    responses.append({
                        "sent": msg,
                        "received": None,
                    })
        
        return {
            "endpoint": request.endpoint,
            "messages_sent": len(request.messages),
            "responses": responses,
        }
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/websocket/techniques")
async def list_websocket_techniques(
    current_user: User = Depends(get_current_active_user)
):
    """
    List available WebSocket attack techniques.
    """
    return {
        "techniques": [
            {
                "id": t.value,
                "name": t.name.replace("_", " ").title(),
                "description": _get_ws_technique_description(t),
            }
            for t in WebSocketAttackType
        ]
    }


def _get_ws_technique_description(technique: WebSocketAttackType) -> str:
    """Get description for a WebSocket attack technique."""
    descriptions = {
        WebSocketAttackType.MESSAGE_INJECTION: "Test for injection vulnerabilities in WebSocket messages",
        WebSocketAttackType.AUTH_BYPASS: "Test authentication bypass scenarios",
        WebSocketAttackType.RACE_CONDITION: "Test for race condition vulnerabilities",
        WebSocketAttackType.RECONNECT_HIJACK: "Test for session hijacking on reconnection",
        WebSocketAttackType.PROTOCOL_CONFUSION: "Test protocol handling vulnerabilities",
        WebSocketAttackType.DOS: "Test for denial of service vulnerabilities",
        WebSocketAttackType.CSWSH: "Test for Cross-Site WebSocket Hijacking",
    }
    return descriptions.get(technique, "No description available")


# =============================================================================
# UTILITY ENDPOINTS
# =============================================================================

@router.get("/detect")
async def detect_protocol(
    url: str,
    current_user: User = Depends(get_current_active_user)
):
    """
    Detect if a URL is a GraphQL or WebSocket endpoint.
    """
    return {
        "url": url,
        "is_graphql": is_graphql_endpoint(url),
        "is_websocket": is_websocket_endpoint(url),
        "websocket_available": WEBSOCKETS_AVAILABLE,
    }


@router.get("/status")
async def get_fuzzer_status(
    current_user: User = Depends(get_current_active_user)
):
    """
    Get protocol fuzzer status and capabilities.
    """
    return {
        "graphql_fuzzing": True,
        "websocket_fuzzing": WEBSOCKETS_AVAILABLE,
        "graphql_techniques": len(GraphQLAttackType),
        "websocket_techniques": len(WebSocketAttackType) if WEBSOCKETS_AVAILABLE else 0,
    }
