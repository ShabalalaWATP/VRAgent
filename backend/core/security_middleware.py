"""
Security middleware for FastAPI application.
Adds security headers and protections against common web vulnerabilities.
"""
from typing import Callable

from fastapi import Request, Response
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.types import ASGIApp

from backend.core.config import settings
from backend.core.logging import get_logger

logger = get_logger(__name__)


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """
    Middleware that adds security headers to all responses.

    These headers protect against:
    - Clickjacking (X-Frame-Options)
    - MIME type sniffing (X-Content-Type-Options)
    - XSS in older browsers (X-XSS-Protection)
    - Information disclosure (X-Powered-By removal, Referrer-Policy)
    - Cross-origin attacks (various headers)
    """

    def __init__(self, app: ASGIApp):
        super().__init__(app)
        self.is_production = settings.environment == "production"

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        response = await call_next(request)

        # Prevent clickjacking - page cannot be embedded in iframes from other origins
        response.headers["X-Frame-Options"] = "SAMEORIGIN"

        # Prevent MIME type sniffing
        response.headers["X-Content-Type-Options"] = "nosniff"

        # XSS protection for older browsers (modern browsers use CSP)
        response.headers["X-XSS-Protection"] = "1; mode=block"

        # Control referrer information sent with requests
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"

        # Remove server identification headers
        if "server" in response.headers:
            del response.headers["server"]
        if "x-powered-by" in response.headers:
            del response.headers["x-powered-by"]

        # Permissions Policy (formerly Feature-Policy)
        # Restrict access to sensitive browser features
        response.headers["Permissions-Policy"] = (
            "accelerometer=(), "
            "camera=(), "
            "geolocation=(), "
            "gyroscope=(), "
            "magnetometer=(), "
            "microphone=(), "
            "payment=(), "
            "usb=()"
        )

        # Content Security Policy - apply to all routes
        # API routes get strict CSP, other routes get standard CSP
        if request.url.path.startswith("/api/") or request.url.path.startswith("/auth/"):
            # Strict CSP for API responses (no resources needed)
            response.headers["Content-Security-Policy"] = (
                "default-src 'none'; "
                "frame-ancestors 'none'"
            )
        elif self.is_production:
            # Standard CSP for other routes in production
            response.headers["Content-Security-Policy"] = (
                "default-src 'self'; "
                "script-src 'self'; "
                "style-src 'self' 'unsafe-inline'; "
                "img-src 'self' data: https:; "
                "font-src 'self'; "
                "frame-ancestors 'none'"
            )

        # Strict Transport Security (HSTS) - only in production with HTTPS
        if self.is_production:
            response.headers["Strict-Transport-Security"] = (
                "max-age=31536000; includeSubDomains; preload"
            )

        # Cross-Origin headers for additional isolation
        response.headers["Cross-Origin-Opener-Policy"] = "same-origin"
        response.headers["Cross-Origin-Resource-Policy"] = "same-origin"

        return response


class OriginValidationMiddleware(BaseHTTPMiddleware):
    """
    Middleware that validates Origin header for state-changing requests.

    This provides defense-in-depth against CSRF-like attacks even though
    the application uses JWT tokens in headers (which are inherently CSRF-safe).

    For state-changing methods (POST, PUT, DELETE, PATCH), validates that:
    1. Origin header (if present) matches allowed origins
    2. Referer header (if no Origin) comes from allowed origins

    This is a secondary protection layer - the primary protection is that
    authentication tokens are not sent automatically by browsers.
    """

    # Allowed origins - extend this list for production deployments
    ALLOWED_ORIGINS = {
        "http://localhost:5173",
        "http://localhost:3000",
        "http://localhost:8080",
        "http://127.0.0.1:5173",
        "http://127.0.0.1:3000",
        "http://127.0.0.1:8080",
    }

    # Methods that modify state and should be validated
    STATE_CHANGING_METHODS = {"POST", "PUT", "DELETE", "PATCH"}

    # Paths that are exempt from origin validation (e.g., webhooks)
    EXEMPT_PATHS = {
        "/health",
        "/health/detailed",
    }

    def __init__(self, app: ASGIApp, additional_origins: list[str] = None):
        super().__init__(app)
        self.allowed_origins = self.ALLOWED_ORIGINS.copy()
        if additional_origins:
            self.allowed_origins.update(additional_origins)

        # Add origins from CORS_ORIGINS env var (for LAN/custom development setups)
        import os
        cors_origins = os.getenv("CORS_ORIGINS", "")
        if cors_origins:
            for origin in cors_origins.split(","):
                origin = origin.strip()
                if origin:
                    self.allowed_origins.add(origin)

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        # Only validate state-changing methods
        if request.method not in self.STATE_CHANGING_METHODS:
            return await call_next(request)

        # Skip exempt paths
        if request.url.path in self.EXEMPT_PATHS:
            return await call_next(request)

        # Get Origin header
        origin = request.headers.get("origin")

        if origin:
            # Validate Origin header
            if origin not in self.allowed_origins:
                logger.warning(
                    f"Blocked request with invalid origin: {origin} "
                    f"for {request.method} {request.url.path}"
                )
                return Response(
                    content='{"error": "Invalid origin"}',
                    status_code=403,
                    media_type="application/json"
                )
        else:
            # No Origin header - check Referer as fallback
            referer = request.headers.get("referer")
            if referer:
                # Extract origin from referer
                from urllib.parse import urlparse
                parsed = urlparse(referer)
                referer_origin = f"{parsed.scheme}://{parsed.netloc}"

                if referer_origin not in self.allowed_origins:
                    logger.warning(
                        f"Blocked request with invalid referer origin: {referer_origin} "
                        f"for {request.method} {request.url.path}"
                    )
                    return Response(
                        content='{"error": "Invalid origin"}',
                        status_code=403,
                        media_type="application/json"
                    )

        return await call_next(request)
