"""
Enhanced Redis Caching Layer for VRAgent
Provides intelligent caching for expensive operations
"""

import hashlib
import json
import logging
from datetime import datetime, date
from typing import Any, Optional, Callable, Union
from functools import wraps
import asyncio

import redis.asyncio as aioredis
from backend.core.config import settings

logger = logging.getLogger(__name__)


def _json_serializer(obj: Any) -> Any:
    """Custom JSON serializer for objects not serializable by default json."""
    if isinstance(obj, (datetime, date)):
        return {"__type__": "datetime", "value": obj.isoformat()}
    elif isinstance(obj, bytes):
        return {"__type__": "bytes", "value": obj.decode("utf-8", errors="replace")}
    elif isinstance(obj, set):
        return {"__type__": "set", "value": list(obj)}
    elif hasattr(obj, "__dict__"):
        return {"__type__": "object", "value": obj.__dict__}
    raise TypeError(f"Object of type {type(obj).__name__} is not JSON serializable")


def _json_deserializer(obj: Any) -> Any:
    """Custom JSON deserializer to restore special types."""
    if isinstance(obj, dict) and "__type__" in obj:
        obj_type = obj["__type__"]
        if obj_type == "datetime":
            return datetime.fromisoformat(obj["value"])
        elif obj_type == "bytes":
            return obj["value"].encode("utf-8")
        elif obj_type == "set":
            return set(obj["value"])
        elif obj_type == "object":
            return obj["value"]
    return obj


def _deserialize_recursive(obj: Any) -> Any:
    """Recursively deserialize JSON objects."""
    if isinstance(obj, dict):
        obj = _json_deserializer(obj)
        if isinstance(obj, dict):
            return {k: _deserialize_recursive(v) for k, v in obj.items()}
        return obj
    elif isinstance(obj, list):
        return [_deserialize_recursive(item) for item in obj]
    return obj


class CacheKey:
    """Generate consistent cache keys"""

    @staticmethod
    def binary_analysis(sha256: str, analysis_type: str) -> str:
        """Cache key for binary analysis results"""
        return f"binary:analysis:{sha256}:{analysis_type}"

    @staticmethod
    def apk_analysis(sha256: str, analysis_type: str) -> str:
        """Cache key for APK analysis results"""
        return f"apk:analysis:{sha256}:{analysis_type}"

    @staticmethod
    def yara_scan(sha256: str) -> str:
        """Cache key for YARA scan results"""
        return f"yara:scan:{sha256}"

    @staticmethod
    def ghidra_decompile(sha256: str, function_address: int) -> str:
        """Cache key for Ghidra decompilation"""
        return f"ghidra:decompile:{sha256}:{function_address:x}"

    @staticmethod
    def ai_analysis(sha256: str, prompt_hash: str) -> str:
        """Cache key for AI analysis results"""
        return f"ai:analysis:{sha256}:{prompt_hash}"

    @staticmethod
    def cve_lookup(cpe: str) -> str:
        """Cache key for CVE lookups"""
        return f"cve:lookup:{cpe}"

    @staticmethod
    def fuzzing_stats(campaign_id: str) -> str:
        """Cache key for fuzzing statistics"""
        return f"fuzzing:stats:{campaign_id}"

    @staticmethod
    def crash_triage(crash_hash: str) -> str:
        """Cache key for crash triage results"""
        return f"crash:triage:{crash_hash}"


class EnhancedCache:
    """
    Enhanced caching layer with multiple strategies.

    Features:
    - Async Redis operations
    - Multiple TTL policies
    - Cache warming
    - Cache invalidation
    - Statistics tracking
    - Compression for large values
    """

    def __init__(self):
        self.redis_url = settings.redis_url
        self._client: Optional[aioredis.Redis] = None

        # TTL policies (in seconds)
        self.ttl_policies = {
            "short": 300,           # 5 minutes
            "medium": 3600,         # 1 hour
            "long": 86400,          # 24 hours
            "week": 604800,         # 7 days
            "month": 2592000,       # 30 days
            "permanent": None,      # No expiration
        }

        # Stats
        self.stats = {
            "hits": 0,
            "misses": 0,
            "sets": 0,
            "deletes": 0,
            "errors": 0,
        }

    async def get_client(self) -> aioredis.Redis:
        """Get or create Redis client"""
        if self._client is None:
            self._client = await aioredis.from_url(
                self.redis_url,
                encoding="utf-8",
                decode_responses=False,  # Handle bytes for pickle
                max_connections=50
            )
        return self._client

    async def get(self, key: str, default: Any = None) -> Optional[Any]:
        """
        Get value from cache.

        Args:
            key: Cache key
            default: Default value if not found

        Returns:
            Cached value or default
        """
        try:
            client = await self.get_client()
            value = await client.get(key)

            if value is None:
                self.stats["misses"] += 1
                return default

            self.stats["hits"] += 1

            # Deserialize JSON (secure alternative to pickle)
            try:
                decoded = value.decode() if isinstance(value, bytes) else value
                parsed = json.loads(decoded)
                return _deserialize_recursive(parsed)
            except (json.JSONDecodeError, UnicodeDecodeError):
                # Fall back to returning raw string
                return value.decode() if isinstance(value, bytes) else value

        except Exception as e:
            logger.error(f"Cache get error for key {key}: {e}")
            self.stats["errors"] += 1
            return default

    async def set(
        self,
        key: str,
        value: Any,
        ttl: Union[int, str, None] = "medium"
    ) -> bool:
        """
        Set value in cache.

        Args:
            key: Cache key
            value: Value to cache
            ttl: Time-to-live (seconds or policy name)

        Returns:
            True if successful
        """
        try:
            client = await self.get_client()

            # Resolve TTL
            if isinstance(ttl, str):
                ttl_seconds = self.ttl_policies.get(ttl, 3600)
            else:
                ttl_seconds = ttl

            # Serialize value using JSON (secure alternative to pickle)
            try:
                serialized = json.dumps(value, default=_json_serializer).encode()
            except (TypeError, ValueError):
                # Fall back to string representation
                serialized = str(value).encode()

            # Set with TTL
            if ttl_seconds:
                await client.setex(key, ttl_seconds, serialized)
            else:
                await client.set(key, serialized)

            self.stats["sets"] += 1
            return True

        except Exception as e:
            logger.error(f"Cache set error for key {key}: {e}")
            self.stats["errors"] += 1
            return False

    async def delete(self, key: str) -> bool:
        """Delete key from cache"""
        try:
            client = await self.get_client()
            await client.delete(key)
            self.stats["deletes"] += 1
            return True
        except Exception as e:
            logger.error(f"Cache delete error for key {key}: {e}")
            self.stats["errors"] += 1
            return False

    async def delete_pattern(self, pattern: str) -> int:
        """
        Delete all keys matching pattern.

        Args:
            pattern: Redis pattern (e.g., "binary:*")

        Returns:
            Number of keys deleted
        """
        try:
            client = await self.get_client()
            keys = []

            # Scan for matching keys
            async for key in client.scan_iter(match=pattern):
                keys.append(key)

            if keys:
                deleted = await client.delete(*keys)
                self.stats["deletes"] += deleted
                return deleted

            return 0

        except Exception as e:
            logger.error(f"Cache delete pattern error for {pattern}: {e}")
            self.stats["errors"] += 1
            return 0

    async def exists(self, key: str) -> bool:
        """Check if key exists in cache"""
        try:
            client = await self.get_client()
            return await client.exists(key) > 0
        except Exception as e:
            logger.error(f"Cache exists error for key {key}: {e}")
            return False

    async def get_ttl(self, key: str) -> int:
        """Get remaining TTL for key (in seconds)"""
        try:
            client = await self.get_client()
            return await client.ttl(key)
        except Exception as e:
            logger.error(f"Cache TTL error for key {key}: {e}")
            return -1

    async def extend_ttl(self, key: str, additional_seconds: int) -> bool:
        """Extend TTL of existing key"""
        try:
            client = await self.get_client()
            current_ttl = await client.ttl(key)

            if current_ttl > 0:
                new_ttl = current_ttl + additional_seconds
                await client.expire(key, new_ttl)
                return True

            return False

        except Exception as e:
            logger.error(f"Cache extend TTL error for key {key}: {e}")
            return False

    async def get_stats(self) -> dict:
        """Get cache statistics"""
        try:
            client = await self.get_client()
            info = await client.info("stats")

            hit_rate = 0.0
            total = self.stats["hits"] + self.stats["misses"]
            if total > 0:
                hit_rate = (self.stats["hits"] / total) * 100

            return {
                "hits": self.stats["hits"],
                "misses": self.stats["misses"],
                "sets": self.stats["sets"],
                "deletes": self.stats["deletes"],
                "errors": self.stats["errors"],
                "hit_rate_percent": hit_rate,
                "redis_info": {
                    "total_commands_processed": info.get("total_commands_processed", 0),
                    "keyspace_hits": info.get("keyspace_hits", 0),
                    "keyspace_misses": info.get("keyspace_misses", 0),
                }
            }

        except Exception as e:
            logger.error(f"Cache stats error: {e}")
            return self.stats

    async def clear_all(self) -> bool:
        """Clear all cache (dangerous!)"""
        try:
            client = await self.get_client()
            await client.flushdb()
            logger.warning("Cache cleared!")
            return True
        except Exception as e:
            logger.error(f"Cache clear error: {e}")
            return False

    async def close(self):
        """Close Redis connection"""
        if self._client:
            await self._client.close()
            self._client = None


# Global cache instance
enhanced_cache = EnhancedCache()


# ============================================================================
# Decorators for Automatic Caching
# ============================================================================

def cached(
    key_generator: Callable,
    ttl: Union[int, str, None] = "medium",
    skip_if: Optional[Callable] = None
):
    """
    Decorator to automatically cache function results.

    Args:
        key_generator: Function to generate cache key from args/kwargs
        ttl: Time-to-live for cache entry
        skip_if: Optional function to determine if caching should be skipped

    Usage:
        @cached(
            key_generator=lambda sha256: CacheKey.binary_analysis(sha256, "standard"),
            ttl="long"
        )
        async def analyze_binary(sha256: str):
            # Expensive operation
            ...
    """
    def decorator(func: Callable) -> Callable:
        @wraps(func)
        async def wrapper(*args, **kwargs):
            # Generate cache key
            try:
                cache_key = key_generator(*args, **kwargs)
            except Exception as e:
                logger.warning(f"Failed to generate cache key for {func.__name__}: {e}")
                # Skip caching, call function directly
                return await func(*args, **kwargs)

            # Check if caching should be skipped
            if skip_if and skip_if(*args, **kwargs):
                return await func(*args, **kwargs)

            # Try to get from cache
            cached_result = await enhanced_cache.get(cache_key)
            if cached_result is not None:
                logger.debug(f"Cache hit for {func.__name__}: {cache_key}")
                return cached_result

            # Cache miss - call function
            logger.debug(f"Cache miss for {func.__name__}: {cache_key}")
            result = await func(*args, **kwargs)

            # Cache result
            await enhanced_cache.set(cache_key, result, ttl=ttl)

            return result

        return wrapper
    return decorator


def cache_invalidate(key_generator: Callable):
    """
    Decorator to invalidate cache after function execution.

    Usage:
        @cache_invalidate(
            key_generator=lambda sha256: CacheKey.binary_analysis(sha256, "*")
        )
        async def update_binary(sha256: str):
            # Update operation that invalidates cache
            ...
    """
    def decorator(func: Callable) -> Callable:
        @wraps(func)
        async def wrapper(*args, **kwargs):
            # Call function first
            result = await func(*args, **kwargs)

            # Invalidate cache
            try:
                cache_key = key_generator(*args, **kwargs)

                # Check if pattern (contains *)
                if "*" in cache_key:
                    deleted = await enhanced_cache.delete_pattern(cache_key)
                    logger.debug(f"Invalidated {deleted} cache entries for {cache_key}")
                else:
                    await enhanced_cache.delete(cache_key)
                    logger.debug(f"Invalidated cache entry: {cache_key}")

            except Exception as e:
                logger.warning(f"Failed to invalidate cache for {func.__name__}: {e}")

            return result

        return wrapper
    return decorator


# ============================================================================
# Helper Functions
# ============================================================================

def hash_prompt(prompt: str) -> str:
    """Generate consistent hash for AI prompts"""
    return hashlib.sha256(prompt.encode()).hexdigest()[:16]


async def warm_cache(keys_and_values: dict, ttl: Union[int, str] = "long"):
    """
    Warm cache with multiple values.

    Args:
        keys_and_values: Dict of {cache_key: value}
        ttl: Time-to-live for all entries
    """
    for key, value in keys_and_values.items():
        await enhanced_cache.set(key, value, ttl=ttl)

    logger.info(f"Warmed cache with {len(keys_and_values)} entries")


async def get_cache_size() -> dict:
    """Get approximate cache size"""
    try:
        client = await enhanced_cache.get_client()
        info = await client.info("memory")

        return {
            "used_memory_human": info.get("used_memory_human", "unknown"),
            "used_memory_bytes": info.get("used_memory", 0),
            "used_memory_peak_human": info.get("used_memory_peak_human", "unknown"),
        }

    except Exception as e:
        logger.error(f"Failed to get cache size: {e}")
        return {}
