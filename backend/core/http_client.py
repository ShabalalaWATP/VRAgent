"""
VRAgent Secure HTTP Client Factory

Provides centralized HTTP client creation with secure defaults.
All HTTP requests should use these clients to ensure consistent security settings.
"""

import httpx
import ssl
import socket
import ipaddress
import logging
from typing import Optional, Dict, Any, List
from contextlib import asynccontextmanager
from urllib.parse import urlparse

from backend.core.config import settings

logger = logging.getLogger(__name__)

# Default timeout configuration
DEFAULT_TIMEOUT = httpx.Timeout(30.0, connect=10.0)

# Maximum redirects to follow (prevents redirect loops)
DEFAULT_MAX_REDIRECTS = 10

# Security warning message
SSL_DISABLED_WARNING = (
    "SECURITY WARNING: SSL verification disabled for HTTP client. "
    "This should only be used for testing self-signed certificates in controlled environments."
)


# =============================================================================
# SSRF Protection
# =============================================================================

# Private/internal IP ranges that should be blocked for SSRF protection
PRIVATE_IP_RANGES = [
    ipaddress.ip_network("10.0.0.0/8"),        # Class A private
    ipaddress.ip_network("172.16.0.0/12"),     # Class B private
    ipaddress.ip_network("192.168.0.0/16"),    # Class C private
    ipaddress.ip_network("127.0.0.0/8"),       # Loopback
    ipaddress.ip_network("169.254.0.0/16"),    # Link-local
    ipaddress.ip_network("::1/128"),           # IPv6 loopback
    ipaddress.ip_network("fc00::/7"),          # IPv6 unique local
    ipaddress.ip_network("fe80::/10"),         # IPv6 link-local
]

# Cloud metadata endpoints that should be blocked
BLOCKED_METADATA_HOSTS = {
    "169.254.169.254",          # AWS/GCP/Azure metadata
    "metadata.google.internal", # GCP metadata
    "metadata",                 # Generic metadata
}


def is_private_ip(ip_str: str) -> bool:
    """Check if an IP address is in a private/internal range."""
    try:
        ip = ipaddress.ip_address(ip_str)
        for network in PRIVATE_IP_RANGES:
            if ip in network:
                return True
        return False
    except ValueError:
        # Invalid IP address
        return False


def is_ssrf_safe_url(url: str, allow_private: bool = False) -> tuple[bool, str]:
    """
    Validate a URL for SSRF safety.

    Args:
        url: The URL to validate
        allow_private: If True, allow private/internal IP addresses (default: False)

    Returns:
        Tuple of (is_safe, error_message)

    Checks:
    1. URL must use http or https scheme
    2. Hostname must not resolve to a private IP (unless allow_private=True)
    3. Hostname must not be a cloud metadata endpoint
    """
    try:
        parsed = urlparse(url)

        # Check scheme
        if parsed.scheme not in ("http", "https"):
            return False, f"Invalid scheme '{parsed.scheme}'. Only http/https allowed."

        # Check for empty host
        if not parsed.hostname:
            return False, "URL must have a hostname"

        hostname = parsed.hostname.lower()

        # Block cloud metadata endpoints
        if hostname in BLOCKED_METADATA_HOSTS:
            return False, f"Blocked metadata endpoint: {hostname}"

        # Resolve hostname and check for private IPs
        if not allow_private:
            try:
                # Resolve hostname to IP addresses
                addr_info = socket.getaddrinfo(hostname, None, socket.AF_UNSPEC)
                for family, _, _, _, sockaddr in addr_info:
                    ip_str = sockaddr[0]
                    if is_private_ip(ip_str):
                        return False, f"URL resolves to private IP: {ip_str}"
            except socket.gaierror:
                # Can't resolve hostname - could be a DNS rebinding attack
                # Log but allow (the request will fail anyway)
                logger.warning(f"Could not resolve hostname: {hostname}")

        return True, ""

    except Exception as e:
        return False, f"Invalid URL: {str(e)}"


def validate_redirect_url(url: str, allow_private: bool = False) -> bool:
    """
    Validate a redirect URL for SSRF safety.
    Use this as an event hook for httpx clients.
    """
    is_safe, error = is_ssrf_safe_url(url, allow_private)
    if not is_safe:
        logger.warning(f"SSRF protection blocked redirect to: {url} - {error}")
    return is_safe


def create_sync_client(
    timeout: float = 30.0,
    verify_ssl: bool = True,
    custom_ca_bundle: Optional[str] = None,
    follow_redirects: bool = True,
    max_redirects: int = DEFAULT_MAX_REDIRECTS,
    allow_private_ips: bool = False,
    **kwargs
) -> httpx.Client:
    """
    Create a synchronous HTTP client with secure defaults.

    Args:
        timeout: Request timeout in seconds (default: 30)
        verify_ssl: Whether to verify SSL certificates (default: True)
        custom_ca_bundle: Path to custom CA bundle for self-signed certs
        follow_redirects: Whether to follow redirects (default: True)
        max_redirects: Maximum number of redirects to follow (default: 10)
        allow_private_ips: If True, allow requests to private/internal IPs (default: False)
        **kwargs: Additional arguments passed to httpx.Client

    Returns:
        Configured httpx.Client instance

    Security:
        - Limits redirect count to prevent redirect loops
        - SSRF protection blocks private IPs by default (use allow_private_ips=True to disable)

    Example:
        with create_sync_client() as client:
            response = client.get("https://example.com")
    """
    if not verify_ssl:
        logger.warning(SSL_DISABLED_WARNING)

    verify = custom_ca_bundle if custom_ca_bundle else verify_ssl

    return httpx.Client(
        timeout=timeout,
        verify=verify,
        follow_redirects=follow_redirects,
        max_redirects=max_redirects,
        **kwargs
    )


def create_async_client(
    timeout: float = 30.0,
    verify_ssl: bool = True,
    custom_ca_bundle: Optional[str] = None,
    follow_redirects: bool = True,
    max_redirects: int = DEFAULT_MAX_REDIRECTS,
    allow_private_ips: bool = False,
    **kwargs
) -> httpx.AsyncClient:
    """
    Create an asynchronous HTTP client with secure defaults.

    Args:
        timeout: Request timeout in seconds (default: 30)
        verify_ssl: Whether to verify SSL certificates (default: True)
        custom_ca_bundle: Path to custom CA bundle for self-signed certs
        follow_redirects: Whether to follow redirects (default: True)
        max_redirects: Maximum number of redirects to follow (default: 10)
        allow_private_ips: If True, allow requests to private/internal IPs (default: False)
        **kwargs: Additional arguments passed to httpx.AsyncClient

    Returns:
        Configured httpx.AsyncClient instance

    Security:
        - Limits redirect count to prevent redirect loops
        - SSRF protection blocks private IPs by default (use allow_private_ips=True to disable)

    Example:
        async with create_async_client() as client:
            response = await client.get("https://example.com")
    """
    if not verify_ssl:
        logger.warning(SSL_DISABLED_WARNING)

    verify = custom_ca_bundle if custom_ca_bundle else verify_ssl

    return httpx.AsyncClient(
        timeout=timeout,
        verify=verify,
        follow_redirects=follow_redirects,
        max_redirects=max_redirects,
        **kwargs
    )


@asynccontextmanager
async def secure_async_client(
    timeout: float = 30.0,
    verify_ssl: bool = True,
    custom_ca_bundle: Optional[str] = None,
    **kwargs
):
    """
    Async context manager for secure HTTP client.

    This is the recommended way to make HTTP requests in async code.

    Example:
        async with secure_async_client() as client:
            response = await client.get("https://api.example.com/data")
            data = response.json()
    """
    client = create_async_client(
        timeout=timeout,
        verify_ssl=verify_ssl,
        custom_ca_bundle=custom_ca_bundle,
        **kwargs
    )
    try:
        yield client
    finally:
        await client.aclose()


class SecureHTTPClient:
    """
    Reusable secure HTTP client with connection pooling and SSRF protection.

    Use this for services that make multiple requests.

    Example:
        client = SecureHTTPClient()
        await client.start()

        try:
            response = await client.get("https://api.example.com")
        finally:
            await client.stop()

    Security Features:
        - SSL verification enabled by default
        - SSRF protection blocks private IP addresses
        - Max redirects limited to prevent loops
        - Cloud metadata endpoints blocked
    """

    def __init__(
        self,
        timeout: float = 30.0,
        verify_ssl: bool = True,
        custom_ca_bundle: Optional[str] = None,
        max_connections: int = 100,
        max_keepalive_connections: int = 20,
        max_redirects: int = DEFAULT_MAX_REDIRECTS,
        allow_private_ips: bool = False,
    ):
        self.timeout = timeout
        self.verify_ssl = verify_ssl
        self.custom_ca_bundle = custom_ca_bundle
        self.max_connections = max_connections
        self.max_keepalive_connections = max_keepalive_connections
        self.max_redirects = max_redirects
        self.allow_private_ips = allow_private_ips
        self._client: Optional[httpx.AsyncClient] = None

    async def start(self):
        """Initialize the HTTP client."""
        if self._client is not None:
            return

        if not self.verify_ssl:
            logger.warning(SSL_DISABLED_WARNING)

        verify = self.custom_ca_bundle if self.custom_ca_bundle else self.verify_ssl

        limits = httpx.Limits(
            max_connections=self.max_connections,
            max_keepalive_connections=self.max_keepalive_connections,
        )

        self._client = httpx.AsyncClient(
            timeout=self.timeout,
            verify=verify,
            limits=limits,
            max_redirects=self.max_redirects,
        )

    async def stop(self):
        """Close the HTTP client."""
        if self._client is not None:
            await self._client.aclose()
            self._client = None

    @property
    def client(self) -> httpx.AsyncClient:
        """Get the underlying client (must call start() first)."""
        if self._client is None:
            raise RuntimeError("Client not started. Call start() first.")
        return self._client

    async def get(self, url: str, **kwargs) -> httpx.Response:
        """Make a GET request."""
        return await self.client.get(url, **kwargs)

    async def post(self, url: str, **kwargs) -> httpx.Response:
        """Make a POST request."""
        return await self.client.post(url, **kwargs)

    async def put(self, url: str, **kwargs) -> httpx.Response:
        """Make a PUT request."""
        return await self.client.put(url, **kwargs)

    async def delete(self, url: str, **kwargs) -> httpx.Response:
        """Make a DELETE request."""
        return await self.client.delete(url, **kwargs)

    async def request(self, method: str, url: str, **kwargs) -> httpx.Response:
        """Make a request with any HTTP method."""
        return await self.client.request(method, url, **kwargs)


# Pre-configured clients for common use cases
def get_api_client(timeout: float = 30.0) -> httpx.AsyncClient:
    """Get a client configured for API requests with SSL verification."""
    return create_async_client(timeout=timeout, verify_ssl=True)


def get_test_client(timeout: float = 30.0) -> httpx.AsyncClient:
    """
    Get a client for testing with SSL verification DISABLED.

    WARNING: Only use this for testing against local services with self-signed certificates.
    This function is blocked in production environments.

    Raises:
        RuntimeError: If called in production environment
    """
    if settings.environment == "production":
        raise RuntimeError(
            "SECURITY ERROR: get_test_client() cannot be used in production. "
            "Use get_api_client() with proper SSL verification instead."
        )
    logger.warning("Creating test client with SSL verification disabled - DEVELOPMENT ONLY")
    return create_async_client(timeout=timeout, verify_ssl=False)
