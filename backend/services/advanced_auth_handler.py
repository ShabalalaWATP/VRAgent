"""
Advanced Authentication Handler Service

Comprehensive authentication handler supporting multiple auth flows,
including SAML, PKCE, OAuth2 authorization code, custom auth schemes,
and MFA handling.
"""

import asyncio
import base64
import hashlib
import secrets
import time
import json
import re
import hmac
import uuid
from typing import Dict, List, Any, Optional, Tuple, Callable
from dataclasses import dataclass, field
from enum import Enum
from urllib.parse import urlencode, urlparse, parse_qs, quote
import logging
from abc import ABC, abstractmethod
import xml.etree.ElementTree as ET
from datetime import datetime, timedelta

import httpx

logger = logging.getLogger(__name__)


class AuthFlowType(Enum):
    """Supported authentication flow types."""
    NONE = "none"
    
    # Basic authentication
    BASIC = "basic"
    DIGEST = "digest"
    NTLM = "ntlm"
    
    # Token-based
    BEARER = "bearer"
    API_KEY = "api_key"
    JWT = "jwt"
    HAWK = "hawk"
    AWS_SIGV4 = "aws_sigv4"
    
    # OAuth flows
    OAUTH2_CLIENT_CREDENTIALS = "oauth2_client_credentials"
    OAUTH2_PASSWORD = "oauth2_password"
    OAUTH2_AUTHORIZATION_CODE = "oauth2_authorization_code"
    OAUTH2_PKCE = "oauth2_pkce"
    OAUTH2_IMPLICIT = "oauth2_implicit"
    OAUTH2_DEVICE_CODE = "oauth2_device_code"
    
    # Enterprise SSO
    SAML = "saml"
    OIDC = "oidc"
    KERBEROS = "kerberos"
    
    # Session-based
    COOKIE_SESSION = "cookie_session"
    FORM_LOGIN = "form_login"
    
    # Custom
    CUSTOM_HEADER = "custom_header"
    CUSTOM_SCRIPT = "custom_script"
    MULTI_STEP = "multi_step"


class TokenLocation(Enum):
    """Where tokens are placed."""
    HEADER = "header"
    QUERY = "query"
    COOKIE = "cookie"
    BODY = "body"
    PATH = "path"


@dataclass
class TokenInfo:
    """Information about an authentication token."""
    access_token: str
    token_type: str = "Bearer"
    expires_at: Optional[float] = None
    refresh_token: Optional[str] = None
    scope: Optional[str] = None
    id_token: Optional[str] = None  # For OIDC
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    @property
    def is_expired(self) -> bool:
        """Check if token is expired."""
        if self.expires_at is None:
            return False
        return time.time() >= self.expires_at
    
    @property
    def should_refresh(self) -> bool:
        """Check if token should be refreshed (with margin)."""
        if self.expires_at is None:
            return False
        # Refresh 60 seconds before expiry
        return time.time() >= self.expires_at - 60


@dataclass
class PKCEChallenge:
    """PKCE challenge data."""
    code_verifier: str
    code_challenge: str
    code_challenge_method: str = "S256"
    
    @classmethod
    def generate(cls) -> "PKCEChallenge":
        """Generate a new PKCE challenge."""
        # Generate code verifier (43-128 chars, unreserved URI chars)
        code_verifier = secrets.token_urlsafe(32)
        
        # Generate code challenge using SHA256
        digest = hashlib.sha256(code_verifier.encode()).digest()
        code_challenge = base64.urlsafe_b64encode(digest).rstrip(b"=").decode()
        
        return cls(
            code_verifier=code_verifier,
            code_challenge=code_challenge,
            code_challenge_method="S256"
        )


@dataclass
class AuthConfig:
    """Comprehensive authentication configuration."""
    flow_type: AuthFlowType = AuthFlowType.NONE
    
    # Basic/Digest Auth
    username: Optional[str] = None
    password: Optional[str] = None
    realm: Optional[str] = None  # For digest
    domain: Optional[str] = None  # For NTLM
    
    # Token/API Key
    token: Optional[str] = None
    token_header: str = "Authorization"
    token_prefix: str = "Bearer"
    api_key_name: str = "X-API-Key"
    api_key_location: TokenLocation = TokenLocation.HEADER
    
    # OAuth2 common
    client_id: Optional[str] = None
    client_secret: Optional[str] = None
    token_url: Optional[str] = None
    authorize_url: Optional[str] = None
    redirect_uri: Optional[str] = None
    scope: Optional[str] = None
    audience: Optional[str] = None
    
    # OAuth2 PKCE
    use_pkce: bool = False
    pkce_challenge: Optional[PKCEChallenge] = None
    
    # OAuth2 Password flow
    resource_owner_username: Optional[str] = None
    resource_owner_password: Optional[str] = None
    
    # SAML
    saml_idp_url: Optional[str] = None
    saml_sp_entity_id: Optional[str] = None
    saml_acs_url: Optional[str] = None
    saml_certificate: Optional[str] = None
    saml_private_key: Optional[str] = None
    
    # Session/Cookie
    session_cookie_name: str = "session"
    session_cookie_value: Optional[str] = None
    login_url: Optional[str] = None
    login_payload: Optional[Dict[str, Any]] = None
    csrf_token_name: Optional[str] = None
    csrf_token_location: Optional[str] = None  # header, body, cookie
    
    # AWS Signature
    aws_access_key: Optional[str] = None
    aws_secret_key: Optional[str] = None
    aws_region: Optional[str] = None
    aws_service: Optional[str] = None
    
    # HAWK
    hawk_id: Optional[str] = None
    hawk_key: Optional[str] = None
    hawk_algorithm: str = "sha256"
    
    # Token refresh
    refresh_token: Optional[str] = None
    refresh_url: Optional[str] = None
    auto_refresh: bool = True
    refresh_margin_seconds: float = 60.0
    
    # MFA
    mfa_enabled: bool = False
    mfa_type: Optional[str] = None  # totp, sms, email, push
    mfa_secret: Optional[str] = None  # For TOTP
    mfa_callback: Optional[Callable[[], str]] = None  # Function to get MFA code
    
    # Custom headers
    custom_headers: Dict[str, str] = field(default_factory=dict)
    
    # Multi-step auth
    auth_steps: List[Dict[str, Any]] = field(default_factory=list)
    
    # Rate limiting
    max_retries: int = 3
    retry_delay: float = 1.0


class AuthHandler(ABC):
    """Base class for authentication handlers."""
    
    @abstractmethod
    async def authenticate(self, client: httpx.AsyncClient) -> TokenInfo:
        """Perform authentication and return token info."""
        pass
    
    @abstractmethod
    async def get_headers(self) -> Dict[str, str]:
        """Get authentication headers for a request."""
        pass
    
    @abstractmethod
    async def refresh(self, client: httpx.AsyncClient) -> TokenInfo:
        """Refresh the authentication token."""
        pass


class BasicAuthHandler(AuthHandler):
    """Handle HTTP Basic authentication."""
    
    def __init__(self, username: str, password: str):
        self.username = username
        self.password = password
        self._credentials = base64.b64encode(
            f"{username}:{password}".encode()
        ).decode()
    
    async def authenticate(self, client: httpx.AsyncClient) -> TokenInfo:
        return TokenInfo(access_token=self._credentials, token_type="Basic")
    
    async def get_headers(self) -> Dict[str, str]:
        return {"Authorization": f"Basic {self._credentials}"}
    
    async def refresh(self, client: httpx.AsyncClient) -> TokenInfo:
        return await self.authenticate(client)


class DigestAuthHandler(AuthHandler):
    """Handle HTTP Digest authentication."""
    
    def __init__(self, username: str, password: str):
        self.username = username
        self.password = password
        self._nonce: Optional[str] = None
        self._realm: Optional[str] = None
        self._qop: Optional[str] = None
        self._opaque: Optional[str] = None
        self._nc = 0
    
    async def authenticate(self, client: httpx.AsyncClient) -> TokenInfo:
        # Digest auth requires a challenge from the server first
        return TokenInfo(access_token="digest", token_type="Digest")
    
    async def get_headers(self) -> Dict[str, str]:
        # Digest headers are computed per-request
        return {}
    
    async def refresh(self, client: httpx.AsyncClient) -> TokenInfo:
        return await self.authenticate(client)
    
    def compute_digest_header(
        self,
        method: str,
        uri: str,
        nonce: str,
        realm: str,
        qop: Optional[str] = None,
        opaque: Optional[str] = None,
    ) -> str:
        """Compute the Digest authorization header."""
        self._nc += 1
        nc = f"{self._nc:08x}"
        cnonce = secrets.token_hex(8)
        
        # Compute HA1
        ha1_data = f"{self.username}:{realm}:{self.password}"
        ha1 = hashlib.md5(ha1_data.encode()).hexdigest()
        
        # Compute HA2
        ha2_data = f"{method}:{uri}"
        ha2 = hashlib.md5(ha2_data.encode()).hexdigest()
        
        # Compute response
        if qop:
            response_data = f"{ha1}:{nonce}:{nc}:{cnonce}:{qop}:{ha2}"
        else:
            response_data = f"{ha1}:{nonce}:{ha2}"
        response = hashlib.md5(response_data.encode()).hexdigest()
        
        # Build header
        parts = [
            f'username="{self.username}"',
            f'realm="{realm}"',
            f'nonce="{nonce}"',
            f'uri="{uri}"',
            f'response="{response}"',
        ]
        
        if qop:
            parts.extend([
                f'qop={qop}',
                f'nc={nc}',
                f'cnonce="{cnonce}"',
            ])
        
        if opaque:
            parts.append(f'opaque="{opaque}"')
        
        return "Digest " + ", ".join(parts)


class OAuth2Handler(AuthHandler):
    """Handle OAuth2 authentication flows."""
    
    def __init__(self, config: AuthConfig):
        self.config = config
        self._token: Optional[TokenInfo] = None
        self._refresh_lock = asyncio.Lock()
    
    async def authenticate(self, client: httpx.AsyncClient) -> TokenInfo:
        """Authenticate using the configured OAuth2 flow."""
        if self.config.flow_type == AuthFlowType.OAUTH2_CLIENT_CREDENTIALS:
            return await self._client_credentials_flow(client)
        elif self.config.flow_type == AuthFlowType.OAUTH2_PASSWORD:
            return await self._password_flow(client)
        elif self.config.flow_type == AuthFlowType.OAUTH2_PKCE:
            return await self._pkce_flow(client)
        elif self.config.flow_type == AuthFlowType.OAUTH2_DEVICE_CODE:
            return await self._device_code_flow(client)
        else:
            raise ValueError(f"Unsupported OAuth2 flow: {self.config.flow_type}")
    
    async def get_headers(self) -> Dict[str, str]:
        if self._token and not self._token.is_expired:
            return {"Authorization": f"{self._token.token_type} {self._token.access_token}"}
        return {}
    
    async def refresh(self, client: httpx.AsyncClient) -> TokenInfo:
        """Refresh the OAuth2 token."""
        async with self._refresh_lock:
            if not self._token or not self._token.refresh_token:
                return await self.authenticate(client)
            
            if not self._token.should_refresh:
                return self._token
            
            try:
                response = await client.post(
                    self.config.token_url,
                    data={
                        "grant_type": "refresh_token",
                        "refresh_token": self._token.refresh_token,
                        "client_id": self.config.client_id,
                        "client_secret": self.config.client_secret,
                    },
                )
                
                if response.status_code == 200:
                    data = response.json()
                    self._token = self._parse_token_response(data)
                    return self._token
                else:
                    logger.error(f"Token refresh failed: {response.status_code}")
                    return await self.authenticate(client)
                    
            except Exception as e:
                logger.error(f"Token refresh error: {e}")
                return await self.authenticate(client)
    
    async def _client_credentials_flow(self, client: httpx.AsyncClient) -> TokenInfo:
        """OAuth2 client credentials flow."""
        data = {
            "grant_type": "client_credentials",
            "client_id": self.config.client_id,
            "client_secret": self.config.client_secret,
        }
        
        if self.config.scope:
            data["scope"] = self.config.scope
        if self.config.audience:
            data["audience"] = self.config.audience
        
        response = await client.post(self.config.token_url, data=data)
        
        if response.status_code == 200:
            self._token = self._parse_token_response(response.json())
            return self._token
        
        raise AuthenticationError(f"OAuth2 client credentials failed: {response.status_code}")
    
    async def _password_flow(self, client: httpx.AsyncClient) -> TokenInfo:
        """OAuth2 resource owner password credentials flow."""
        data = {
            "grant_type": "password",
            "username": self.config.resource_owner_username,
            "password": self.config.resource_owner_password,
            "client_id": self.config.client_id,
        }
        
        if self.config.client_secret:
            data["client_secret"] = self.config.client_secret
        if self.config.scope:
            data["scope"] = self.config.scope
        
        response = await client.post(self.config.token_url, data=data)
        
        if response.status_code == 200:
            self._token = self._parse_token_response(response.json())
            return self._token
        
        raise AuthenticationError(f"OAuth2 password flow failed: {response.status_code}")
    
    async def _pkce_flow(self, client: httpx.AsyncClient) -> TokenInfo:
        """OAuth2 Authorization Code flow with PKCE."""
        # Generate PKCE challenge if not provided
        if not self.config.pkce_challenge:
            self.config.pkce_challenge = PKCEChallenge.generate()
        
        # Step 1: Build authorization URL
        auth_params = {
            "client_id": self.config.client_id,
            "response_type": "code",
            "redirect_uri": self.config.redirect_uri,
            "code_challenge": self.config.pkce_challenge.code_challenge,
            "code_challenge_method": self.config.pkce_challenge.code_challenge_method,
            "state": secrets.token_urlsafe(16),
        }
        
        if self.config.scope:
            auth_params["scope"] = self.config.scope
        
        auth_url = f"{self.config.authorize_url}?{urlencode(auth_params)}"
        
        logger.info(f"PKCE authorization URL: {auth_url}")
        
        # In a real implementation, this would redirect the user and handle the callback
        # For fuzzing purposes, we'll assume we have the authorization code
        # This would typically come from a callback handler
        
        # Return a placeholder token with the auth URL for manual completion
        return TokenInfo(
            access_token="",
            token_type="pkce_pending",
            metadata={
                "status": "pending_authorization",
                "auth_url": auth_url,
                "message": "PKCE flow requires user interaction. Visit the auth_url to complete authorization.",
            }
        )
    
    async def exchange_pkce_code(
        self, 
        client: httpx.AsyncClient, 
        authorization_code: str
    ) -> TokenInfo:
        """Exchange authorization code for tokens (PKCE flow completion)."""
        if not self.config.pkce_challenge:
            raise AuthenticationError("PKCE challenge not found")
        
        data = {
            "grant_type": "authorization_code",
            "code": authorization_code,
            "redirect_uri": self.config.redirect_uri,
            "client_id": self.config.client_id,
            "code_verifier": self.config.pkce_challenge.code_verifier,
        }
        
        response = await client.post(self.config.token_url, data=data)
        
        if response.status_code == 200:
            self._token = self._parse_token_response(response.json())
            return self._token
        
        raise AuthenticationError(f"PKCE token exchange failed: {response.status_code}")
    
    async def _device_code_flow(self, client: httpx.AsyncClient) -> TokenInfo:
        """OAuth2 Device Authorization flow."""
        # Step 1: Request device code
        device_response = await client.post(
            self.config.authorize_url,  # Device authorization endpoint
            data={
                "client_id": self.config.client_id,
                "scope": self.config.scope or "",
            }
        )
        
        if device_response.status_code != 200:
            raise AuthenticationError(f"Device code request failed: {device_response.status_code}")
        
        device_data = device_response.json()
        device_code = device_data["device_code"]
        user_code = device_data["user_code"]
        verification_uri = device_data["verification_uri"]
        interval = device_data.get("interval", 5)
        expires_in = device_data.get("expires_in", 600)
        
        logger.info(f"Device code flow: Visit {verification_uri} and enter code: {user_code}")
        
        # Step 2: Poll for token
        start_time = time.time()
        while time.time() - start_time < expires_in:
            await asyncio.sleep(interval)
            
            token_response = await client.post(
                self.config.token_url,
                data={
                    "grant_type": "urn:ietf:params:oauth:grant-type:device_code",
                    "device_code": device_code,
                    "client_id": self.config.client_id,
                }
            )
            
            if token_response.status_code == 200:
                self._token = self._parse_token_response(token_response.json())
                return self._token
            
            error_data = token_response.json()
            error = error_data.get("error")
            
            if error == "authorization_pending":
                continue
            elif error == "slow_down":
                interval += 5
            else:
                raise AuthenticationError(f"Device code flow error: {error}")
        
        raise AuthenticationError("Device code flow timed out")
    
    def _parse_token_response(self, data: Dict[str, Any]) -> TokenInfo:
        """Parse OAuth2 token response."""
        expires_at = None
        if "expires_in" in data:
            expires_at = time.time() + data["expires_in"]
        
        return TokenInfo(
            access_token=data["access_token"],
            token_type=data.get("token_type", "Bearer"),
            expires_at=expires_at,
            refresh_token=data.get("refresh_token"),
            scope=data.get("scope"),
            id_token=data.get("id_token"),
            metadata=data,
        )
    
    def get_authorize_url(self, state: Optional[str] = None) -> str:
        """Get the OAuth2 authorization URL for interactive flows."""
        params = {
            "client_id": self.config.client_id,
            "response_type": "code",
            "redirect_uri": self.config.redirect_uri,
            "state": state or secrets.token_urlsafe(16),
        }
        
        if self.config.scope:
            params["scope"] = self.config.scope
        
        if self.config.use_pkce:
            if not self.config.pkce_challenge:
                self.config.pkce_challenge = PKCEChallenge.generate()
            params["code_challenge"] = self.config.pkce_challenge.code_challenge
            params["code_challenge_method"] = self.config.pkce_challenge.code_challenge_method
        
        return f"{self.config.authorize_url}?{urlencode(params)}"


class SAMLHandler(AuthHandler):
    """Handle SAML authentication."""
    
    def __init__(self, config: AuthConfig):
        self.config = config
        self._assertion: Optional[str] = None
        self._session_cookies: Dict[str, str] = {}
    
    async def authenticate(self, client: httpx.AsyncClient) -> TokenInfo:
        """Initiate SAML authentication flow."""
        # Create SAML AuthnRequest
        authn_request = self._create_authn_request()
        
        # Encode and prepare for redirect
        encoded_request = base64.b64encode(authn_request.encode()).decode()
        
        saml_url = f"{self.config.saml_idp_url}?SAMLRequest={quote(encoded_request)}"
        
        logger.info(f"SAML authentication URL: {saml_url}")
        
        # In a real implementation, this would redirect to IdP
        # Return a placeholder token with the SAML URL for manual completion
        return TokenInfo(
            access_token="",
            token_type="saml_pending",
            metadata={
                "status": "pending_authentication",
                "saml_url": saml_url,
                "message": "SAML authentication requires user interaction. Visit the saml_url to complete authentication.",
            }
        )
    
    async def get_headers(self) -> Dict[str, str]:
        return {}
    
    async def refresh(self, client: httpx.AsyncClient) -> TokenInfo:
        return await self.authenticate(client)
    
    async def process_saml_response(
        self, 
        client: httpx.AsyncClient,
        saml_response: str
    ) -> TokenInfo:
        """Process SAML response from IdP."""
        try:
            # Decode and parse SAML response
            decoded = base64.b64decode(saml_response)
            root = ET.fromstring(decoded)
            
            # Extract assertions and attributes
            namespaces = {
                'saml': 'urn:oasis:names:tc:SAML:2.0:assertion',
                'samlp': 'urn:oasis:names:tc:SAML:2.0:protocol',
            }
            
            # Find assertion
            assertion = root.find('.//saml:Assertion', namespaces)
            if assertion is None:
                raise AuthenticationError("No SAML assertion found")
            
            # Extract attributes
            attributes = {}
            attr_statements = assertion.findall('.//saml:AttributeStatement/saml:Attribute', namespaces)
            for attr in attr_statements:
                name = attr.get('Name')
                values = [v.text for v in attr.findall('saml:AttributeValue', namespaces)]
                attributes[name] = values[0] if len(values) == 1 else values
            
            # Post assertion to SP's ACS URL
            if self.config.saml_acs_url:
                response = await client.post(
                    self.config.saml_acs_url,
                    data={"SAMLResponse": saml_response}
                )
                
                # Extract session cookies
                for cookie in response.cookies:
                    self._session_cookies[cookie.name] = cookie.value
            
            self._assertion = saml_response
            
            return TokenInfo(
                access_token=saml_response,
                token_type="SAML",
                metadata={"attributes": attributes},
            )
            
        except ET.ParseError as e:
            raise AuthenticationError(f"Invalid SAML response: {e}")
    
    def _create_authn_request(self) -> str:
        """Create a SAML AuthnRequest."""
        request_id = f"_{''.join(secrets.token_hex(16))}"
        issue_instant = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")
        
        authn_request = f"""<?xml version="1.0" encoding="UTF-8"?>
<samlp:AuthnRequest 
    xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
    xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
    ID="{request_id}"
    Version="2.0"
    IssueInstant="{issue_instant}"
    Destination="{self.config.saml_idp_url}"
    AssertionConsumerServiceURL="{self.config.saml_acs_url}"
    ProtocolBinding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST">
    <saml:Issuer>{self.config.saml_sp_entity_id}</saml:Issuer>
    <samlp:NameIDPolicy 
        Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"
        AllowCreate="true"/>
</samlp:AuthnRequest>"""
        
        return authn_request
    
    def get_session_cookies(self) -> Dict[str, str]:
        """Get session cookies established after SAML auth."""
        return self._session_cookies.copy()


class AWSSignatureV4Handler(AuthHandler):
    """Handle AWS Signature Version 4 authentication."""
    
    def __init__(self, config: AuthConfig):
        self.config = config
    
    async def authenticate(self, client: httpx.AsyncClient) -> TokenInfo:
        return TokenInfo(
            access_token="aws_sigv4",
            token_type="AWS4-HMAC-SHA256",
        )
    
    async def get_headers(self) -> Dict[str, str]:
        # AWS Signature headers are computed per-request
        return {}
    
    async def refresh(self, client: httpx.AsyncClient) -> TokenInfo:
        return await self.authenticate(client)
    
    def sign_request(
        self,
        method: str,
        url: str,
        headers: Dict[str, str],
        payload: str = "",
    ) -> Dict[str, str]:
        """Sign a request using AWS Signature V4."""
        parsed = urlparse(url)
        host = parsed.netloc
        path = parsed.path or "/"
        query = parsed.query
        
        # Date/time
        t = datetime.utcnow()
        amz_date = t.strftime("%Y%m%dT%H%M%SZ")
        date_stamp = t.strftime("%Y%m%d")
        
        # Create canonical request
        headers["host"] = host
        headers["x-amz-date"] = amz_date
        
        canonical_headers = "\n".join(
            f"{k.lower()}:{v.strip()}"
            for k, v in sorted(headers.items())
        ) + "\n"
        
        signed_headers = ";".join(sorted(k.lower() for k in headers.keys()))
        
        payload_hash = hashlib.sha256(payload.encode()).hexdigest()
        
        canonical_request = "\n".join([
            method.upper(),
            path,
            query,
            canonical_headers,
            signed_headers,
            payload_hash,
        ])
        
        # Create string to sign
        algorithm = "AWS4-HMAC-SHA256"
        credential_scope = f"{date_stamp}/{self.config.aws_region}/{self.config.aws_service}/aws4_request"
        
        string_to_sign = "\n".join([
            algorithm,
            amz_date,
            credential_scope,
            hashlib.sha256(canonical_request.encode()).hexdigest(),
        ])
        
        # Calculate signature
        def sign(key: bytes, msg: str) -> bytes:
            return hmac.new(key, msg.encode(), hashlib.sha256).digest()
        
        k_date = sign(f"AWS4{self.config.aws_secret_key}".encode(), date_stamp)
        k_region = sign(k_date, self.config.aws_region)
        k_service = sign(k_region, self.config.aws_service)
        k_signing = sign(k_service, "aws4_request")
        
        signature = hmac.new(k_signing, string_to_sign.encode(), hashlib.sha256).hexdigest()
        
        # Build authorization header
        auth_header = (
            f"{algorithm} "
            f"Credential={self.config.aws_access_key}/{credential_scope}, "
            f"SignedHeaders={signed_headers}, "
            f"Signature={signature}"
        )
        
        return {
            "Authorization": auth_header,
            "x-amz-date": amz_date,
            "x-amz-content-sha256": payload_hash,
        }


class FormLoginHandler(AuthHandler):
    """Handle form-based login authentication."""
    
    def __init__(self, config: AuthConfig):
        self.config = config
        self._session_cookies: Dict[str, str] = {}
        self._csrf_token: Optional[str] = None
    
    async def authenticate(self, client: httpx.AsyncClient) -> TokenInfo:
        """Perform form-based login."""
        # Step 1: Get login page to extract CSRF token
        if self.config.csrf_token_name:
            login_page = await client.get(self.config.login_url)
            self._csrf_token = self._extract_csrf_token(login_page.text)
        
        # Step 2: Prepare login payload
        payload = dict(self.config.login_payload or {})
        
        if self._csrf_token and self.config.csrf_token_name:
            payload[self.config.csrf_token_name] = self._csrf_token
        
        # Step 3: Submit login
        response = await client.post(
            self.config.login_url,
            data=payload,
            follow_redirects=True,
        )
        
        # Step 4: Extract session cookies
        for cookie in client.cookies.jar:
            self._session_cookies[cookie.name] = cookie.value
        
        # Check if login was successful
        if response.status_code in (200, 302) and self._session_cookies:
            session_value = self._session_cookies.get(
                self.config.session_cookie_name, ""
            )
            return TokenInfo(
                access_token=session_value,
                token_type="Session",
                metadata={"cookies": self._session_cookies},
            )
        
        raise AuthenticationError(f"Form login failed: {response.status_code}")
    
    async def get_headers(self) -> Dict[str, str]:
        return {}
    
    async def refresh(self, client: httpx.AsyncClient) -> TokenInfo:
        return await self.authenticate(client)
    
    def get_cookies(self) -> Dict[str, str]:
        """Get session cookies."""
        return self._session_cookies.copy()
    
    def _extract_csrf_token(self, html: str) -> Optional[str]:
        """Extract CSRF token from HTML."""
        if not self.config.csrf_token_name:
            return None
        
        # Try hidden input field
        pattern = rf'name=["\']?{re.escape(self.config.csrf_token_name)}["\']?\s+value=["\']?([^"\'>\s]+)'
        match = re.search(pattern, html, re.IGNORECASE)
        if match:
            return match.group(1)
        
        # Try meta tag
        pattern = rf'<meta\s+name=["\']?{re.escape(self.config.csrf_token_name)}["\']?\s+content=["\']?([^"\']+)'
        match = re.search(pattern, html, re.IGNORECASE)
        if match:
            return match.group(1)
        
        return None


class MultiStepAuthHandler(AuthHandler):
    """Handle multi-step authentication flows."""
    
    def __init__(self, config: AuthConfig):
        self.config = config
        self._tokens: List[TokenInfo] = []
        self._session_data: Dict[str, Any] = {}
    
    async def authenticate(self, client: httpx.AsyncClient) -> TokenInfo:
        """Execute multi-step authentication."""
        for i, step in enumerate(self.config.auth_steps):
            logger.info(f"Executing auth step {i + 1}/{len(self.config.auth_steps)}")
            
            step_type = step.get("type", "request")
            
            if step_type == "request":
                await self._execute_request_step(client, step)
            elif step_type == "extract":
                self._execute_extract_step(step)
            elif step_type == "wait":
                await asyncio.sleep(step.get("duration", 1))
            elif step_type == "mfa":
                await self._execute_mfa_step(client, step)
        
        # Return the final token
        if self._tokens:
            return self._tokens[-1]
        
        raise AuthenticationError("Multi-step auth completed but no token obtained")
    
    async def get_headers(self) -> Dict[str, str]:
        if self._tokens:
            token = self._tokens[-1]
            return {"Authorization": f"{token.token_type} {token.access_token}"}
        return {}
    
    async def refresh(self, client: httpx.AsyncClient) -> TokenInfo:
        return await self.authenticate(client)
    
    async def _execute_request_step(
        self, 
        client: httpx.AsyncClient, 
        step: Dict[str, Any]
    ):
        """Execute a request step."""
        method = step.get("method", "POST").upper()
        url = self._interpolate(step["url"])
        headers = {
            k: self._interpolate(v) 
            for k, v in step.get("headers", {}).items()
        }
        
        data = None
        json_data = None
        
        if "body" in step:
            body = step["body"]
            if isinstance(body, dict):
                body = {k: self._interpolate(str(v)) for k, v in body.items()}
            if step.get("content_type") == "json":
                json_data = body
            else:
                data = body
        
        response = await client.request(
            method, url,
            headers=headers,
            data=data,
            json=json_data,
        )
        
        # Store response for extraction
        self._session_data["last_response"] = response
        self._session_data["last_body"] = response.text
        
        # Auto-extract common tokens
        try:
            response_json = response.json()
            if "access_token" in response_json:
                self._tokens.append(TokenInfo(
                    access_token=response_json["access_token"],
                    token_type=response_json.get("token_type", "Bearer"),
                    refresh_token=response_json.get("refresh_token"),
                ))
        except json.JSONDecodeError:
            pass
    
    def _execute_extract_step(self, step: Dict[str, Any]):
        """Execute an extraction step."""
        source = step.get("source", "body")
        pattern = step.get("pattern")
        variable = step.get("variable")
        
        if source == "body":
            text = self._session_data.get("last_body", "")
        elif source == "header":
            response = self._session_data.get("last_response")
            header_name = step.get("header")
            text = response.headers.get(header_name, "") if response else ""
        else:
            text = ""
        
        if pattern and variable:
            match = re.search(pattern, text)
            if match:
                self._session_data[variable] = match.group(1) if match.groups() else match.group()
    
    async def _execute_mfa_step(
        self, 
        client: httpx.AsyncClient, 
        step: Dict[str, Any]
    ):
        """Execute an MFA step."""
        mfa_type = step.get("mfa_type", "totp")
        
        if mfa_type == "totp" and self.config.mfa_secret:
            # Generate TOTP code
            code = self._generate_totp(self.config.mfa_secret)
        elif self.config.mfa_callback:
            # Use callback to get code
            code = self.config.mfa_callback()
        else:
            raise AuthenticationError("MFA required but no code available")
        
        # Submit MFA code
        url = self._interpolate(step["url"])
        data = {k: self._interpolate(str(v)) for k, v in step.get("body", {}).items()}
        data[step.get("code_field", "code")] = code
        
        response = await client.post(url, data=data)
        self._session_data["last_response"] = response
        self._session_data["last_body"] = response.text
    
    def _interpolate(self, value: str) -> str:
        """Interpolate variables in a string."""
        for var_name, var_value in self._session_data.items():
            if isinstance(var_value, str):
                value = value.replace(f"{{{var_name}}}", var_value)
        return value
    
    def _generate_totp(self, secret: str, interval: int = 30) -> str:
        """Generate TOTP code."""
        # Decode base32 secret
        key = base64.b32decode(secret.upper() + "=" * ((8 - len(secret) % 8) % 8))
        
        # Calculate counter
        counter = int(time.time() // interval)
        
        # Generate HMAC
        counter_bytes = counter.to_bytes(8, byteorder="big")
        hmac_hash = hmac.new(key, counter_bytes, hashlib.sha1).digest()
        
        # Extract OTP
        offset = hmac_hash[-1] & 0x0f
        code = (
            (hmac_hash[offset] & 0x7f) << 24 |
            (hmac_hash[offset + 1] & 0xff) << 16 |
            (hmac_hash[offset + 2] & 0xff) << 8 |
            (hmac_hash[offset + 3] & 0xff)
        )
        
        return str(code % 1000000).zfill(6)


class AuthenticationError(Exception):
    """Authentication error."""
    pass


class AdvancedAuthManager:
    """
    Advanced authentication manager that coordinates multiple auth handlers
    and provides a unified interface for authenticated requests.
    """
    
    def __init__(self, config: AuthConfig):
        self.config = config
        self._handler: Optional[AuthHandler] = None
        self._token: Optional[TokenInfo] = None
        self._client: Optional[httpx.AsyncClient] = None
        self._refresh_lock = asyncio.Lock()
        self._initialize_handler()
    
    def _initialize_handler(self):
        """Initialize the appropriate auth handler."""
        if self.config.flow_type == AuthFlowType.NONE:
            self._handler = None
        elif self.config.flow_type == AuthFlowType.BASIC:
            self._handler = BasicAuthHandler(
                self.config.username,
                self.config.password,
            )
        elif self.config.flow_type == AuthFlowType.DIGEST:
            self._handler = DigestAuthHandler(
                self.config.username,
                self.config.password,
            )
        elif self.config.flow_type in (
            AuthFlowType.OAUTH2_CLIENT_CREDENTIALS,
            AuthFlowType.OAUTH2_PASSWORD,
            AuthFlowType.OAUTH2_PKCE,
            AuthFlowType.OAUTH2_DEVICE_CODE,
        ):
            self._handler = OAuth2Handler(self.config)
        elif self.config.flow_type == AuthFlowType.SAML:
            self._handler = SAMLHandler(self.config)
        elif self.config.flow_type == AuthFlowType.AWS_SIGV4:
            self._handler = AWSSignatureV4Handler(self.config)
        elif self.config.flow_type == AuthFlowType.FORM_LOGIN:
            self._handler = FormLoginHandler(self.config)
        elif self.config.flow_type == AuthFlowType.MULTI_STEP:
            self._handler = MultiStepAuthHandler(self.config)
        else:
            self._handler = None
    
    async def authenticate(self) -> TokenInfo:
        """Perform initial authentication."""
        if not self._handler:
            return TokenInfo(access_token="", token_type="None")
        
        async with httpx.AsyncClient(timeout=30) as client:
            self._token = await self._handler.authenticate(client)
            return self._token
    
    async def get_auth_headers(self) -> Dict[str, str]:
        """Get authentication headers for a request."""
        headers = dict(self.config.custom_headers)
        
        # Ensure we have a valid token
        if self._handler and self._token:
            if self._token.should_refresh and self.config.auto_refresh:
                await self._refresh_token()
        
        # Get handler-specific headers
        if self._handler:
            handler_headers = await self._handler.get_headers()
            headers.update(handler_headers)
        
        # Handle bearer/API key if no handler
        if not self._handler and self.config.token:
            if self.config.flow_type == AuthFlowType.BEARER:
                headers[self.config.token_header] = \
                    f"{self.config.token_prefix} {self.config.token}"
            elif self.config.flow_type == AuthFlowType.API_KEY:
                if self.config.api_key_location == TokenLocation.HEADER:
                    headers[self.config.api_key_name] = self.config.token
        
        return headers
    
    async def get_auth_params(self) -> Dict[str, str]:
        """Get authentication query parameters."""
        params = {}
        
        if self.config.flow_type == AuthFlowType.API_KEY:
            if self.config.api_key_location == TokenLocation.QUERY:
                params[self.config.api_key_name] = self.config.token or ""
        
        return params
    
    async def get_auth_cookies(self) -> Dict[str, str]:
        """Get authentication cookies."""
        cookies = {}
        
        if self.config.flow_type == AuthFlowType.API_KEY:
            if self.config.api_key_location == TokenLocation.COOKIE:
                cookies[self.config.api_key_name] = self.config.token or ""
        
        if self.config.flow_type == AuthFlowType.COOKIE_SESSION:
            if self.config.session_cookie_value:
                cookies[self.config.session_cookie_name] = self.config.session_cookie_value
        
        if isinstance(self._handler, FormLoginHandler):
            cookies.update(self._handler.get_cookies())
        
        if isinstance(self._handler, SAMLHandler):
            cookies.update(self._handler.get_session_cookies())
        
        return cookies
    
    async def _refresh_token(self):
        """Refresh the authentication token."""
        async with self._refresh_lock:
            if self._token and not self._token.should_refresh:
                return
            
            async with httpx.AsyncClient(timeout=30) as client:
                self._token = await self._handler.refresh(client)
    
    def sign_request(
        self,
        method: str,
        url: str,
        headers: Dict[str, str],
        payload: str = "",
    ) -> Dict[str, str]:
        """Sign a request (for AWS SigV4, Digest, etc.)."""
        if isinstance(self._handler, AWSSignatureV4Handler):
            return self._handler.sign_request(method, url, headers, payload)
        
        if isinstance(self._handler, DigestAuthHandler):
            parsed = urlparse(url)
            return {
                "Authorization": self._handler.compute_digest_header(
                    method, 
                    parsed.path or "/",
                    nonce="",  # Would come from 401 response
                    realm="",  # Would come from 401 response
                )
            }
        
        return {}
    
    async def handle_auth_challenge(
        self,
        response: httpx.Response,
    ) -> Optional[Dict[str, str]]:
        """Handle authentication challenges (401 responses)."""
        if response.status_code != 401:
            return None
        
        www_auth = response.headers.get("WWW-Authenticate", "")
        
        if www_auth.startswith("Digest"):
            if isinstance(self._handler, DigestAuthHandler):
                # Parse challenge
                parts = dict(re.findall(r'(\w+)="?([^",]+)"?', www_auth))
                
                return {
                    "Authorization": self._handler.compute_digest_header(
                        method="GET",  # Should be actual method
                        uri="/",  # Should be actual URI
                        nonce=parts.get("nonce", ""),
                        realm=parts.get("realm", ""),
                        qop=parts.get("qop"),
                        opaque=parts.get("opaque"),
                    )
                }
        
        return None
    
    def get_current_token(self) -> Optional[TokenInfo]:
        """Get the current token info."""
        return self._token


# Singleton instance
_auth_manager: Optional[AdvancedAuthManager] = None


def get_auth_manager(config: Optional[AuthConfig] = None) -> AdvancedAuthManager:
    """Get or create the auth manager instance."""
    global _auth_manager
    if _auth_manager is None or config is not None:
        _auth_manager = AdvancedAuthManager(config or AuthConfig())
    return _auth_manager
