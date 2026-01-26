"""
Tests for resource limiting system
"""

import pytest
import asyncio
import time
from unittest.mock import Mock, patch

from backend.core.resource_limits import (
    ResourceLimiter,
    ResourceLimits,
    ResourceUsage,
    ResourceLimitExceeded,
    TimeoutExceeded,
    SystemResourceChecker,
    limit_small,
    limit_medium,
    limit_large,
    limit_xlarge,
)


@pytest.mark.asyncio
class TestResourceLimiter:
    """Test ResourceLimiter class"""

    async def test_get_current_usage(self):
        """Test getting current resource usage"""
        limiter = ResourceLimiter()
        limiter._start_time = time.time()

        usage = limiter.get_current_usage()

        assert isinstance(usage, ResourceUsage)
        assert usage.memory_mb > 0
        assert usage.memory_percent >= 0
        assert usage.cpu_percent >= 0
        assert usage.elapsed_seconds >= 0
        assert usage.pid > 0

    async def test_check_limits_within_bounds(self):
        """Test check_limits with normal usage"""
        limiter = ResourceLimiter(
            limits=ResourceLimits(
                max_memory_gb=16.0,
                max_memory_percent=90.0,
                timeout_seconds=3600
            )
        )
        limiter._start_time = time.time()

        usage = ResourceUsage(
            memory_mb=1000,  # 1GB
            memory_percent=10.0,
            cpu_percent=20.0,
            elapsed_seconds=10.0,
            pid=1234
        )

        # Should not raise
        limiter.check_limits(usage)

    async def test_check_limits_memory_exceeded(self):
        """Test check_limits with memory limit exceeded"""
        limiter = ResourceLimiter(
            limits=ResourceLimits(
                max_memory_gb=1.0,  # 1GB limit
                timeout_seconds=3600
            )
        )

        usage = ResourceUsage(
            memory_mb=2000,  # 2GB used
            memory_percent=20.0,
            cpu_percent=20.0,
            elapsed_seconds=10.0,
            pid=1234
        )

        with pytest.raises(ResourceLimitExceeded) as exc_info:
            limiter.check_limits(usage)

        assert exc_info.value.resource == "memory_mb"
        assert exc_info.value.current == 2000
        assert exc_info.value.limit == 1024

    async def test_check_limits_timeout_exceeded(self):
        """Test check_limits with timeout exceeded"""
        limiter = ResourceLimiter(
            limits=ResourceLimits(
                max_memory_gb=16.0,
                timeout_seconds=60  # 1 minute
            )
        )

        usage = ResourceUsage(
            memory_mb=1000,
            memory_percent=10.0,
            cpu_percent=20.0,
            elapsed_seconds=120.0,  # 2 minutes elapsed
            pid=1234
        )

        with pytest.raises(TimeoutExceeded) as exc_info:
            limiter.check_limits(usage)

        assert exc_info.value.elapsed == 120.0
        assert exc_info.value.limit == 60.0

    async def test_monitor_context_manager(self):
        """Test resource monitoring context manager"""
        limiter = ResourceLimiter(
            limits=ResourceLimits(
                max_memory_gb=16.0,
                timeout_seconds=10,
                check_interval_seconds=0.1
            )
        )

        async with limiter.monitor():
            # Do some work
            await asyncio.sleep(0.2)

        # Should complete without error

    async def test_monitor_catches_memory_limit(self):
        """Test that monitor catches memory limit exceeded"""
        # Create limiter with very low memory limit
        limiter = ResourceLimiter(
            limits=ResourceLimits(
                max_memory_gb=0.001,  # 1MB - will definitely exceed
                timeout_seconds=10,
                check_interval_seconds=0.1
            )
        )

        with pytest.raises(ResourceLimitExceeded):
            async with limiter.monitor():
                # Allocate some memory
                data = bytearray(10 * 1024 * 1024)  # 10MB
                await asyncio.sleep(0.5)

    async def test_monitor_catches_timeout(self):
        """Test that monitor catches timeout"""
        limiter = ResourceLimiter(
            limits=ResourceLimits(
                max_memory_gb=16.0,
                timeout_seconds=0.5,  # Very short timeout
                check_interval_seconds=0.1
            )
        )

        with pytest.raises(TimeoutExceeded):
            async with limiter.monitor():
                # Sleep longer than timeout
                await asyncio.sleep(1.0)

    async def test_decorator_protects_function(self):
        """Test that decorator protects function with limits"""
        limiter = ResourceLimiter(
            limits=ResourceLimits(
                max_memory_gb=16.0,
                timeout_seconds=2,
                check_interval_seconds=0.1
            )
        )

        @limiter.limit(max_memory_gb=16.0, timeout_seconds=2)
        async def protected_function():
            await asyncio.sleep(0.2)
            return "success"

        result = await protected_function()
        assert result == "success"

    async def test_decorator_catches_timeout(self):
        """Test that decorator catches timeout"""
        limiter = ResourceLimiter()

        @limiter.limit(max_memory_gb=16.0, timeout_seconds=0.5)
        async def slow_function():
            await asyncio.sleep(1.0)
            return "should not reach"

        with pytest.raises(TimeoutExceeded):
            await slow_function()


@pytest.mark.asyncio
class TestPresetDecorators:
    """Test preset decorator functions"""

    async def test_limit_small(self):
        """Test @limit_small decorator (2GB, 5min)"""
        @limit_small
        async def small_operation():
            await asyncio.sleep(0.1)
            return "done"

        result = await small_operation()
        assert result == "done"

    async def test_limit_medium(self):
        """Test @limit_medium decorator (4GB, 15min)"""
        @limit_medium
        async def medium_operation():
            await asyncio.sleep(0.1)
            return "done"

        result = await medium_operation()
        assert result == "done"

    async def test_limit_large(self):
        """Test @limit_large decorator (8GB, 1hr)"""
        @limit_large
        async def large_operation():
            await asyncio.sleep(0.1)
            return "done"

        result = await large_operation()
        assert result == "done"

    async def test_limit_xlarge(self):
        """Test @limit_xlarge decorator (16GB, 2hr)"""
        @limit_xlarge
        async def xlarge_operation():
            await asyncio.sleep(0.1)
            return "done"

        result = await xlarge_operation()
        assert result == "done"


class TestSystemResourceChecker:
    """Test SystemResourceChecker class"""

    def test_check_available_memory(self):
        """Test checking available memory"""
        # Should have at least 0.1GB free
        has_memory = SystemResourceChecker.check_available_memory(0.1)
        assert isinstance(has_memory, bool)

        # Should not have 1000GB free (unlikely)
        has_huge_memory = SystemResourceChecker.check_available_memory(1000.0)
        assert has_huge_memory == False

    def test_check_available_disk(self):
        """Test checking available disk space"""
        # Check current directory
        has_disk = SystemResourceChecker.check_available_disk(".", 0.1)
        assert isinstance(has_disk, bool)

        # Should not have 10TB free
        has_huge_disk = SystemResourceChecker.check_available_disk(".", 10000.0)
        assert has_huge_disk == False

    def test_get_system_stats(self):
        """Test getting system statistics"""
        stats = SystemResourceChecker.get_system_stats()

        assert isinstance(stats, dict)
        assert "memory" in stats
        assert "disk" in stats
        assert "cpu" in stats

        # Check memory stats
        memory = stats["memory"]
        assert "total_gb" in memory
        assert "available_gb" in memory
        assert "used_percent" in memory
        assert memory["total_gb"] > 0
        assert 0 <= memory["used_percent"] <= 100

        # Check disk stats
        disk = stats["disk"]
        assert "total_gb" in disk
        assert "free_gb" in disk
        assert "used_percent" in disk
        assert disk["total_gb"] > 0

        # Check CPU stats
        cpu = stats["cpu"]
        assert "percent" in cpu
        assert "count" in cpu
        assert cpu["count"] > 0

    def test_can_accept_operation_success(self):
        """Test can_accept_operation with sufficient resources"""
        # Request minimal resources (0.1GB)
        can_accept, reason = SystemResourceChecker.can_accept_operation(0.1)

        assert isinstance(can_accept, bool)
        assert isinstance(reason, str)

        if can_accept:
            assert reason == "OK"

    def test_can_accept_operation_insufficient_memory(self):
        """Test can_accept_operation with insufficient memory"""
        # Request ridiculous amount of memory
        can_accept, reason = SystemResourceChecker.can_accept_operation(10000.0)

        assert can_accept == False
        assert "memory" in reason.lower() or "insufficient" in reason.lower()


class TestResourceLimitExceptions:
    """Test custom exception classes"""

    def test_resource_limit_exceeded(self):
        """Test ResourceLimitExceeded exception"""
        exc = ResourceLimitExceeded("memory", 10.0, 8.0)

        assert exc.resource == "memory"
        assert exc.current == 10.0
        assert exc.limit == 8.0
        assert "memory" in str(exc)
        assert "10.00" in str(exc)
        assert "8.00" in str(exc)

    def test_timeout_exceeded(self):
        """Test TimeoutExceeded exception"""
        exc = TimeoutExceeded(3700.0, 3600.0)

        assert exc.elapsed == 3700.0
        assert exc.limit == 3600.0
        assert "3700.0" in str(exc)
        assert "3600.0" in str(exc)


@pytest.mark.asyncio
class TestResourceLimitIntegration:
    """Integration tests for resource limiting"""

    async def test_memory_intensive_operation(self):
        """Test resource limiter with memory-intensive operation"""
        @limit_small  # 2GB limit
        async def allocate_memory():
            # Allocate 100MB (should be fine)
            data = bytearray(100 * 1024 * 1024)
            await asyncio.sleep(0.1)
            return len(data)

        result = await allocate_memory()
        assert result == 100 * 1024 * 1024

    async def test_timeout_operation(self):
        """Test resource limiter with timeout"""
        limiter = ResourceLimiter(
            limits=ResourceLimits(
                max_memory_gb=16.0,
                timeout_seconds=1.0,
                check_interval_seconds=0.2
            )
        )

        @limiter.limit(timeout_seconds=1.0)
        async def long_operation():
            await asyncio.sleep(2.0)  # Longer than timeout
            return "should not reach"

        with pytest.raises(TimeoutExceeded):
            await long_operation()

    async def test_multiple_concurrent_operations(self):
        """Test multiple operations with resource limits"""
        @limit_small
        async def operation(n: int):
            await asyncio.sleep(0.1)
            return n * 2

        # Run 5 operations concurrently
        results = await asyncio.gather(
            operation(1),
            operation(2),
            operation(3),
            operation(4),
            operation(5)
        )

        assert results == [2, 4, 6, 8, 10]

    async def test_nested_resource_limits(self):
        """Test nested function calls with resource limits"""
        @limit_small
        async def inner_operation():
            await asyncio.sleep(0.1)
            return "inner"

        @limit_medium
        async def outer_operation():
            result = await inner_operation()
            await asyncio.sleep(0.1)
            return f"outer-{result}"

        result = await outer_operation()
        assert result == "outer-inner"


class TestResourceLimitsConfiguration:
    """Test ResourceLimits configuration"""

    def test_default_limits(self):
        """Test default resource limits"""
        limits = ResourceLimits()

        assert limits.max_memory_gb == 8.0
        assert limits.max_memory_percent == 80.0
        assert limits.max_cpu_percent == 80.0
        assert limits.timeout_seconds == 3600
        assert limits.check_interval_seconds == 5.0

    def test_custom_limits(self):
        """Test custom resource limits"""
        limits = ResourceLimits(
            max_memory_gb=4.0,
            max_memory_percent=70.0,
            max_cpu_percent=90.0,
            timeout_seconds=1800,
            check_interval_seconds=10.0
        )

        assert limits.max_memory_gb == 4.0
        assert limits.max_memory_percent == 70.0
        assert limits.max_cpu_percent == 90.0
        assert limits.timeout_seconds == 1800
        assert limits.check_interval_seconds == 10.0


class TestEdgeCases:
    """Test edge cases and boundary conditions"""

    def test_zero_memory_limit(self):
        """Test behavior with zero memory limit"""
        limiter = ResourceLimiter(
            limits=ResourceLimits(max_memory_gb=0.0)
        )

        usage = ResourceUsage(
            memory_mb=100,
            memory_percent=1.0,
            cpu_percent=1.0,
            elapsed_seconds=1.0,
            pid=1234
        )

        # Should raise immediately
        with pytest.raises(ResourceLimitExceeded):
            limiter.check_limits(usage)

    def test_very_high_limits(self):
        """Test behavior with very high limits"""
        limiter = ResourceLimiter(
            limits=ResourceLimits(
                max_memory_gb=1000.0,  # 1TB
                timeout_seconds=86400   # 24 hours
            )
        )

        usage = ResourceUsage(
            memory_mb=1000,  # 1GB
            memory_percent=1.0,
            cpu_percent=1.0,
            elapsed_seconds=60.0,
            pid=1234
        )

        # Should not raise
        limiter.check_limits(usage)

    def test_system_under_stress(self):
        """Test SystemResourceChecker under stress conditions"""
        # Simulate high resource usage
        stats = SystemResourceChecker.get_system_stats()

        # Even under stress, stats should be valid
        assert stats["memory"]["used_percent"] <= 100
        assert stats["disk"]["used_percent"] <= 100
        assert stats["cpu"]["percent"] >= 0


if __name__ == "__main__":
    pytest.main([__file__, "-v", "-s"])
