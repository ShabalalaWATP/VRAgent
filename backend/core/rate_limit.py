"""
Rate limiting middleware for multi-user deployments.
Prevents any single user from overwhelming the system.
"""
from fastapi import Request, HTTPException, status
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware
import time
import asyncio
from collections import defaultdict
from typing import Dict, Tuple
import logging

logger = logging.getLogger(__name__)


class RateLimitMiddleware(BaseHTTPMiddleware):
    """
    Token bucket rate limiting per user/IP.
    
    Limits:
    - Authenticated users: 100 requests/minute
    - Unauthenticated: 20 requests/minute
    - Scan endpoints: 5 scans/minute per user
    """
    
    def __init__(self, app, default_limit: int = 100, window_seconds: int = 60):
        super().__init__(app)
        self.default_limit = default_limit
        self.window_seconds = window_seconds
        # Dict of {identifier: (request_count, window_start_time)}
        self.requests: Dict[str, Tuple[int, float]] = defaultdict(lambda: (0, time.time()))
        self.lock = asyncio.Lock()
        
        # Special limits for expensive endpoints
        self.endpoint_limits = {
            "/api/scans": 5,  # Max 5 scan starts per minute
            "/api/projects": 20,  # Max 20 project operations per minute
            "/api/exploitability": 10,  # Max 10 exploitability checks per minute
            "/api/fuzzing": 5,  # Max 5 fuzzing operations per minute
        }
    
    def _get_identifier(self, request: Request) -> str:
        """Get unique identifier for rate limiting (user_id or IP)."""
        # Try to get user from request state (set by auth middleware)
        user = getattr(request.state, "user", None)
        if user and hasattr(user, "id"):
            return f"user:{user.id}"
        
        # Fall back to IP address
        forwarded = request.headers.get("x-forwarded-for")
        if forwarded:
            return f"ip:{forwarded.split(',')[0].strip()}"
        return f"ip:{request.client.host if request.client else 'unknown'}"
    
    def _get_limit_for_path(self, path: str, is_authenticated: bool) -> int:
        """Get rate limit for specific endpoint."""
        # Check special endpoint limits
        for endpoint, limit in self.endpoint_limits.items():
            if path.startswith(endpoint):
                return limit
        
        # Authenticated users get higher limits
        if is_authenticated:
            return self.default_limit
        return 20  # Lower limit for unauthenticated requests
    
    async def dispatch(self, request: Request, call_next):
        # Skip rate limiting for health checks and static files
        if request.url.path in ["/health", "/docs", "/openapi.json", "/redoc"]:
            return await call_next(request)
        
        identifier = self._get_identifier(request)
        is_authenticated = identifier.startswith("user:")
        limit = self._get_limit_for_path(request.url.path, is_authenticated)
        
        async with self.lock:
            current_time = time.time()
            count, window_start = self.requests[identifier]
            
            # Reset window if expired
            if current_time - window_start >= self.window_seconds:
                self.requests[identifier] = (1, current_time)
            elif count >= limit:
                # Rate limit exceeded
                retry_after = int(self.window_seconds - (current_time - window_start))
                logger.warning(
                    f"Rate limit exceeded for {identifier} on {request.url.path}. "
                    f"Count: {count}/{limit}"
                )
                return JSONResponse(
                    status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                    content={
                        "detail": "Rate limit exceeded. Please try again later.",
                        "retry_after": retry_after
                    },
                    headers={"Retry-After": str(retry_after)}
                )
            else:
                self.requests[identifier] = (count + 1, window_start)
        
        response = await call_next(request)
        
        # Add rate limit headers
        async with self.lock:
            count, _ = self.requests[identifier]
            response.headers["X-RateLimit-Limit"] = str(limit)
            response.headers["X-RateLimit-Remaining"] = str(max(0, limit - count))
            response.headers["X-RateLimit-Reset"] = str(int(window_start + self.window_seconds))
        
        return response


class ConcurrentScanLimitMiddleware(BaseHTTPMiddleware):
    """
    Limits concurrent scans per user to prevent resource exhaustion.
    """
    
    def __init__(self, app, max_concurrent_per_user: int = 3):
        super().__init__(app)
        self.max_concurrent = max_concurrent_per_user
        # Dict of {user_id: active_scan_count}
        self.active_scans: Dict[str, int] = defaultdict(int)
        self.lock = asyncio.Lock()
    
    async def dispatch(self, request: Request, call_next):
        # Only apply to scan creation endpoints
        if not (request.method == "POST" and "/scans" in request.url.path):
            return await call_next(request)
        
        user = getattr(request.state, "user", None)
        if not user or not hasattr(user, "id"):
            return await call_next(request)
        
        user_id = str(user.id)
        
        async with self.lock:
            if self.active_scans[user_id] >= self.max_concurrent:
                return JSONResponse(
                    status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                    content={
                        "detail": f"Maximum concurrent scans ({self.max_concurrent}) reached. "
                                  "Please wait for existing scans to complete."
                    }
                )
            self.active_scans[user_id] += 1
        
        try:
            response = await call_next(request)
            return response
        finally:
            # Note: This is simplified. In production, track via scan completion webhooks
            pass
