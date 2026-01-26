"""
Tests for enhanced caching system
"""

import pytest
import asyncio
from unittest.mock import Mock, patch, AsyncMock

from backend.core.cache_enhanced import (
    EnhancedCache,
    CacheKey,
    cached,
    cache_invalidate,
    hash_prompt,
    warm_cache,
    enhanced_cache,
)


@pytest.mark.asyncio
class TestEnhancedCache:
    """Test EnhancedCache class"""

    async def test_get_set_basic(self):
        """Test basic get/set operations"""
        cache = EnhancedCache()

        # Set value
        await cache.set("test_key", "test_value")

        # Get value
        result = await cache.get("test_key")
        assert result == "test_value"

    async def test_get_nonexistent_key(self):
        """Test getting non-existent key returns default"""
        cache = EnhancedCache()

        result = await cache.get("nonexistent", default="default_value")
        assert result == "default_value"

    async def test_set_with_ttl(self):
        """Test setting value with TTL"""
        cache = EnhancedCache()

        # Set with short TTL
        await cache.set("ttl_key", "ttl_value", ttl=1)

        # Should exist immediately
        assert await cache.exists("ttl_key")

        # Wait for expiration
        await asyncio.sleep(2)

        # Should be gone
        result = await cache.get("ttl_key")
        assert result is None

    async def test_set_with_ttl_policy(self):
        """Test setting value with TTL policy name"""
        cache = EnhancedCache()

        # Set with policy
        await cache.set("policy_key", "policy_value", ttl="short")

        # Should exist
        assert await cache.exists("policy_key")

    async def test_delete(self):
        """Test deleting key"""
        cache = EnhancedCache()

        await cache.set("delete_key", "delete_value")
        assert await cache.exists("delete_key")

        await cache.delete("delete_key")
        assert not await cache.exists("delete_key")

    async def test_delete_pattern(self):
        """Test deleting keys by pattern"""
        cache = EnhancedCache()

        # Set multiple keys
        await cache.set("test:1", "value1")
        await cache.set("test:2", "value2")
        await cache.set("test:3", "value3")
        await cache.set("other:1", "value4")

        # Delete pattern
        deleted = await cache.delete_pattern("test:*")
        assert deleted == 3

        # Verify
        assert not await cache.exists("test:1")
        assert not await cache.exists("test:2")
        assert not await cache.exists("test:3")
        assert await cache.exists("other:1")

    async def test_complex_object_caching(self):
        """Test caching complex Python objects"""
        cache = EnhancedCache()

        complex_obj = {
            "list": [1, 2, 3],
            "dict": {"nested": "value"},
            "tuple": (1, 2, 3),
        }

        await cache.set("complex_key", complex_obj)
        result = await cache.get("complex_key")

        assert result == complex_obj
        assert isinstance(result["list"], list)
        assert isinstance(result["dict"], dict)

    async def test_get_ttl(self):
        """Test getting remaining TTL"""
        cache = EnhancedCache()

        await cache.set("ttl_test", "value", ttl=3600)
        ttl = await cache.get_ttl("ttl_test")

        # Should be close to 3600 (allow some variation)
        assert 3590 < ttl <= 3600

    async def test_extend_ttl(self):
        """Test extending TTL"""
        cache = EnhancedCache()

        await cache.set("extend_test", "value", ttl=10)
        initial_ttl = await cache.get_ttl("extend_test")

        # Extend by 100 seconds
        await cache.extend_ttl("extend_test", 100)
        new_ttl = await cache.get_ttl("extend_test")

        assert new_ttl > initial_ttl + 90  # Allow some variation

    async def test_stats_tracking(self):
        """Test cache statistics tracking"""
        cache = EnhancedCache()

        # Reset stats
        cache.stats = {"hits": 0, "misses": 0, "sets": 0, "deletes": 0, "errors": 0}

        # Perform operations
        await cache.set("stats_key", "value")
        await cache.get("stats_key")  # Hit
        await cache.get("nonexistent")  # Miss
        await cache.delete("stats_key")

        stats = await cache.get_stats()

        assert stats["hits"] >= 1
        assert stats["misses"] >= 1
        assert stats["sets"] >= 1
        assert stats["deletes"] >= 1


class TestCacheKey:
    """Test CacheKey helper class"""

    def test_binary_analysis_key(self):
        """Test binary analysis cache key generation"""
        key = CacheKey.binary_analysis("abc123", "standard")
        assert key == "binary:analysis:abc123:standard"

    def test_apk_analysis_key(self):
        """Test APK analysis cache key generation"""
        key = CacheKey.apk_analysis("def456", "deep")
        assert key == "apk:analysis:def456:deep"

    def test_yara_scan_key(self):
        """Test YARA scan cache key generation"""
        key = CacheKey.yara_scan("ghi789")
        assert key == "yara:scan:ghi789"

    def test_ghidra_decompile_key(self):
        """Test Ghidra decompilation cache key"""
        key = CacheKey.ghidra_decompile("jkl012", 0x401000)
        assert key == "ghidra:decompile:jkl012:401000"

    def test_ai_analysis_key(self):
        """Test AI analysis cache key"""
        key = CacheKey.ai_analysis("mno345", "prompt_hash_123")
        assert key == "ai:analysis:mno345:prompt_hash_123"


@pytest.mark.asyncio
class TestCachedDecorator:
    """Test @cached decorator"""

    async def test_cached_function(self):
        """Test caching function results"""
        call_count = 0

        @cached(
            key_generator=lambda x: f"test:{x}",
            ttl="short"
        )
        async def expensive_function(value: str):
            nonlocal call_count
            call_count += 1
            return f"result:{value}"

        # First call - should hit function
        result1 = await expensive_function("test")
        assert result1 == "result:test"
        assert call_count == 1

        # Second call - should hit cache
        result2 = await expensive_function("test")
        assert result2 == "result:test"
        assert call_count == 1  # Not incremented

        # Different arg - should hit function
        result3 = await expensive_function("other")
        assert result3 == "result:other"
        assert call_count == 2

    async def test_cached_skip_if(self):
        """Test skipping cache conditionally"""
        call_count = 0

        @cached(
            key_generator=lambda x: f"skip:{x}",
            ttl="short",
            skip_if=lambda x: x == "no_cache"
        )
        async def conditional_cache(value: str):
            nonlocal call_count
            call_count += 1
            return f"result:{value}"

        # Should cache
        await conditional_cache("test")
        await conditional_cache("test")
        assert call_count == 1

        # Should skip cache
        await conditional_cache("no_cache")
        await conditional_cache("no_cache")
        assert call_count == 3  # Called twice


@pytest.mark.asyncio
class TestCacheInvalidateDecorator:
    """Test @cache_invalidate decorator"""

    async def test_invalidate_single_key(self):
        """Test invalidating single cache key"""
        cache = EnhancedCache()

        # Set cache value
        await cache.set("invalidate:test", "value")
        assert await cache.exists("invalidate:test")

        # Function with invalidation
        @cache_invalidate(
            key_generator=lambda: "invalidate:test"
        )
        async def update_operation():
            return "updated"

        # Call function
        await update_operation()

        # Cache should be invalidated
        assert not await cache.exists("invalidate:test")

    async def test_invalidate_pattern(self):
        """Test invalidating cache pattern"""
        cache = EnhancedCache()

        # Set multiple cache values
        await cache.set("pattern:1", "value1")
        await cache.set("pattern:2", "value2")
        await cache.set("pattern:3", "value3")

        # Function with pattern invalidation
        @cache_invalidate(
            key_generator=lambda: "pattern:*"
        )
        async def bulk_update():
            return "updated"

        # Call function
        await bulk_update()

        # All pattern keys should be invalidated
        assert not await cache.exists("pattern:1")
        assert not await cache.exists("pattern:2")
        assert not await cache.exists("pattern:3")


class TestHelperFunctions:
    """Test helper functions"""

    def test_hash_prompt(self):
        """Test prompt hashing"""
        hash1 = hash_prompt("test prompt")
        hash2 = hash_prompt("test prompt")
        hash3 = hash_prompt("different prompt")

        # Same prompt = same hash
        assert hash1 == hash2

        # Different prompt = different hash
        assert hash1 != hash3

        # Should be 16 characters
        assert len(hash1) == 16

    @pytest.mark.asyncio
    async def test_warm_cache(self):
        """Test cache warming"""
        cache = EnhancedCache()

        # Warm cache
        data = {
            "warm:1": "value1",
            "warm:2": "value2",
            "warm:3": "value3",
        }

        await warm_cache(data, ttl="long")

        # Verify all keys exist
        assert await cache.exists("warm:1")
        assert await cache.exists("warm:2")
        assert await cache.exists("warm:3")

        # Verify values
        assert await cache.get("warm:1") == "value1"
        assert await cache.get("warm:2") == "value2"
        assert await cache.get("warm:3") == "value3"


@pytest.mark.asyncio
class TestCacheIntegration:
    """Integration tests for caching"""

    async def test_end_to_end_caching(self):
        """Test complete caching workflow"""
        cache = EnhancedCache()

        # Simulate binary analysis caching
        sha256 = "abc123def456"
        analysis_result = {
            "architecture": "x86_64",
            "functions": ["main", "init", "cleanup"],
            "imports": ["libc.so.6"],
            "is_packed": False
        }

        # Cache result
        key = CacheKey.binary_analysis(sha256, "standard")
        await cache.set(key, analysis_result, ttl="long")

        # Retrieve from cache
        cached_result = await cache.get(key)

        assert cached_result == analysis_result
        assert cached_result["architecture"] == "x86_64"
        assert len(cached_result["functions"]) == 3

        # Invalidate
        await cache.delete(key)
        assert not await cache.exists(key)

    async def test_concurrent_caching(self):
        """Test concurrent cache operations"""
        cache = EnhancedCache()

        async def set_value(key: str, value: str):
            await cache.set(key, value)
            return await cache.get(key)

        # Run concurrent operations
        results = await asyncio.gather(
            set_value("concurrent:1", "value1"),
            set_value("concurrent:2", "value2"),
            set_value("concurrent:3", "value3"),
            set_value("concurrent:4", "value4"),
            set_value("concurrent:5", "value5"),
        )

        assert len(results) == 5
        assert "value1" in results
        assert "value2" in results


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
