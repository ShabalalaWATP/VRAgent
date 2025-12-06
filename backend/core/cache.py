"""
Redis Cache Service for VRAgent.

Provides caching for expensive API calls (CVE/NVD/EPSS lookups) to reduce
latency and external API load. Many projects share common dependencies
(lodash, requests, express, etc.) so caching provides significant benefits.
"""

import json
import hashlib
from datetime import timedelta
from typing import Any, Dict, List, Optional, TypeVar, Callable
from functools import wraps

import redis

from backend.core.config import settings
from backend.core.logging import get_logger

logger = get_logger(__name__)

T = TypeVar('T')

# Cache TTL defaults (in seconds)
CACHE_TTL = {
    "osv": 60 * 60 * 24,       # 24 hours - CVE data changes slowly
    "nvd": 60 * 60 * 24,       # 24 hours - NVD data changes slowly  
    "epss": 60 * 60 * 12,      # 12 hours - EPSS updates daily
    "embedding": 60 * 60 * 24 * 7,  # 7 days - embeddings don't change
    "default": 60 * 60 * 6,    # 6 hours - default
}

# Cache key prefixes
CACHE_PREFIX = "vragent"


class RedisCache:
    """Redis cache wrapper with JSON serialization and error handling."""
    
    def __init__(self):
        self._client: Optional[redis.Redis] = None
        self._connected = False
        self._connection_attempted = False
    
    @property
    def client(self) -> Optional[redis.Redis]:
        """Lazy connection to Redis."""
        if not self._connection_attempted:
            self._connection_attempted = True
            try:
                self._client = redis.from_url(
                    settings.redis_url,
                    decode_responses=True,
                    socket_connect_timeout=2,
                    socket_timeout=2,
                )
                # Test connection
                self._client.ping()
                self._connected = True
                logger.info("Redis cache connected successfully")
            except Exception as e:
                logger.warning(f"Redis cache unavailable (will continue without cache): {e}")
                self._client = None
                self._connected = False
        return self._client
    
    @property
    def is_connected(self) -> bool:
        """Check if Redis is available."""
        return self._connected and self.client is not None
    
    def _make_key(self, namespace: str, key: str) -> str:
        """Create a namespaced cache key."""
        return f"{CACHE_PREFIX}:{namespace}:{key}"
    
    def _hash_key(self, data: Any) -> str:
        """Create a hash key from complex data."""
        if isinstance(data, str):
            return hashlib.sha256(data.encode()).hexdigest()[:32]
        return hashlib.sha256(json.dumps(data, sort_keys=True).encode()).hexdigest()[:32]
    
    def get(self, namespace: str, key: str) -> Optional[Any]:
        """
        Get a cached value.
        
        Args:
            namespace: Cache namespace (e.g., "osv", "nvd", "epss")
            key: Cache key
            
        Returns:
            Cached value or None if not found/expired
        """
        if not self.is_connected:
            return None
        
        try:
            cache_key = self._make_key(namespace, key)
            value = self.client.get(cache_key)
            if value:
                return json.loads(value)
        except Exception as e:
            logger.debug(f"Cache get error for {namespace}:{key}: {e}")
        return None
    
    def set(
        self, 
        namespace: str, 
        key: str, 
        value: Any, 
        ttl: Optional[int] = None
    ) -> bool:
        """
        Set a cached value.
        
        Args:
            namespace: Cache namespace
            key: Cache key
            value: Value to cache (must be JSON serializable)
            ttl: Time-to-live in seconds (uses namespace default if not specified)
            
        Returns:
            True if successful, False otherwise
        """
        if not self.is_connected:
            return False
        
        try:
            cache_key = self._make_key(namespace, key)
            ttl = ttl or CACHE_TTL.get(namespace, CACHE_TTL["default"])
            self.client.setex(cache_key, ttl, json.dumps(value))
            return True
        except Exception as e:
            logger.debug(f"Cache set error for {namespace}:{key}: {e}")
            return False
    
    def get_many(self, namespace: str, keys: List[str]) -> Dict[str, Any]:
        """
        Get multiple cached values at once (uses pipeline for efficiency).
        
        Args:
            namespace: Cache namespace
            keys: List of cache keys
            
        Returns:
            Dictionary of key -> value for found items
        """
        if not self.is_connected or not keys:
            return {}
        
        try:
            cache_keys = [self._make_key(namespace, k) for k in keys]
            values = self.client.mget(cache_keys)
            
            results = {}
            for key, value in zip(keys, values):
                if value:
                    try:
                        results[key] = json.loads(value)
                    except json.JSONDecodeError:
                        pass
            return results
        except Exception as e:
            logger.debug(f"Cache get_many error for {namespace}: {e}")
            return {}
    
    def set_many(
        self, 
        namespace: str, 
        items: Dict[str, Any], 
        ttl: Optional[int] = None
    ) -> int:
        """
        Set multiple cached values at once (uses pipeline for efficiency).
        
        Args:
            namespace: Cache namespace
            items: Dictionary of key -> value pairs
            ttl: Time-to-live in seconds
            
        Returns:
            Number of items successfully cached
        """
        if not self.is_connected or not items:
            return 0
        
        try:
            ttl = ttl or CACHE_TTL.get(namespace, CACHE_TTL["default"])
            pipe = self.client.pipeline()
            
            for key, value in items.items():
                cache_key = self._make_key(namespace, key)
                pipe.setex(cache_key, ttl, json.dumps(value))
            
            pipe.execute()
            return len(items)
        except Exception as e:
            logger.debug(f"Cache set_many error for {namespace}: {e}")
            return 0
    
    def delete(self, namespace: str, key: str) -> bool:
        """Delete a cached value."""
        if not self.is_connected:
            return False
        
        try:
            cache_key = self._make_key(namespace, key)
            self.client.delete(cache_key)
            return True
        except Exception as e:
            logger.debug(f"Cache delete error for {namespace}:{key}: {e}")
            return False
    
    def clear_namespace(self, namespace: str) -> int:
        """
        Clear all keys in a namespace.
        
        Args:
            namespace: Cache namespace to clear
            
        Returns:
            Number of keys deleted
        """
        if not self.is_connected:
            return 0
        
        try:
            pattern = self._make_key(namespace, "*")
            keys = list(self.client.scan_iter(match=pattern, count=1000))
            if keys:
                return self.client.delete(*keys)
            return 0
        except Exception as e:
            logger.debug(f"Cache clear error for namespace {namespace}: {e}")
            return 0
    
    def get_stats(self) -> Dict[str, Any]:
        """Get cache statistics."""
        if not self.is_connected:
            return {"connected": False}
        
        try:
            info = self.client.info("stats")
            memory = self.client.info("memory")
            
            # Count keys per namespace
            namespaces = ["osv", "nvd", "epss", "embedding"]
            namespace_counts = {}
            for ns in namespaces:
                pattern = self._make_key(ns, "*")
                count = sum(1 for _ in self.client.scan_iter(match=pattern, count=100))
                namespace_counts[ns] = count
            
            return {
                "connected": True,
                "hits": info.get("keyspace_hits", 0),
                "misses": info.get("keyspace_misses", 0),
                "memory_used": memory.get("used_memory_human", "unknown"),
                "keys_by_namespace": namespace_counts,
            }
        except Exception as e:
            return {"connected": True, "error": str(e)}


# Global cache instance
cache = RedisCache()


def cached(
    namespace: str,
    key_func: Optional[Callable[..., str]] = None,
    ttl: Optional[int] = None,
):
    """
    Decorator to cache function results.
    
    Args:
        namespace: Cache namespace
        key_func: Function to generate cache key from args (default: uses first arg)
        ttl: Cache TTL in seconds
        
    Example:
        @cached("nvd", key_func=lambda cve_id: cve_id)
        async def lookup_cve(cve_id: str) -> dict:
            ...
    """
    def decorator(func: Callable[..., T]) -> Callable[..., T]:
        @wraps(func)
        async def async_wrapper(*args, **kwargs) -> T:
            # Generate cache key
            if key_func:
                cache_key = key_func(*args, **kwargs)
            elif args:
                cache_key = str(args[0])
            else:
                cache_key = cache._hash_key((args, kwargs))
            
            # Try to get from cache
            cached_value = cache.get(namespace, cache_key)
            if cached_value is not None:
                logger.debug(f"Cache hit for {namespace}:{cache_key}")
                return cached_value
            
            # Call function and cache result
            result = await func(*args, **kwargs)
            if result is not None:
                cache.set(namespace, cache_key, result, ttl)
            
            return result
        
        @wraps(func)
        def sync_wrapper(*args, **kwargs) -> T:
            # Generate cache key
            if key_func:
                cache_key = key_func(*args, **kwargs)
            elif args:
                cache_key = str(args[0])
            else:
                cache_key = cache._hash_key((args, kwargs))
            
            # Try to get from cache
            cached_value = cache.get(namespace, cache_key)
            if cached_value is not None:
                logger.debug(f"Cache hit for {namespace}:{cache_key}")
                return cached_value
            
            # Call function and cache result
            result = func(*args, **kwargs)
            if result is not None:
                cache.set(namespace, cache_key, result, ttl)
            
            return result
        
        import asyncio
        if asyncio.iscoroutinefunction(func):
            return async_wrapper
        return sync_wrapper
    
    return decorator
