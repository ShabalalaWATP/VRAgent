"""
VRAgent Resource Limiter - Prevent OOM and CPU Exhaustion
Enforces memory and CPU limits for multi-user production environment
"""

import psutil
import asyncio
import logging
import time
from typing import Optional, Callable, Any
from functools import wraps
from dataclasses import dataclass
from contextlib import asynccontextmanager

logger = logging.getLogger(__name__)


@dataclass
class ResourceLimits:
    """Resource limit configuration"""
    max_memory_gb: float = 8.0
    max_memory_percent: float = 80.0  # % of system memory
    max_cpu_percent: float = 80.0
    timeout_seconds: int = 3600  # 1 hour default
    check_interval_seconds: float = 5.0


@dataclass
class ResourceUsage:
    """Current resource usage snapshot"""
    memory_mb: float
    memory_percent: float
    cpu_percent: float
    elapsed_seconds: float
    pid: int


class ResourceLimitExceeded(Exception):
    """Raised when resource limit is exceeded"""
    def __init__(self, resource: str, current: float, limit: float):
        self.resource = resource
        self.current = current
        self.limit = limit
        super().__init__(
            f"Resource limit exceeded: {resource} = {current:.2f} (limit: {limit:.2f})"
        )


class TimeoutExceeded(Exception):
    """Raised when operation timeout is exceeded"""
    def __init__(self, elapsed: float, limit: float):
        self.elapsed = elapsed
        self.limit = limit
        super().__init__(
            f"Operation timeout: {elapsed:.1f}s (limit: {limit:.1f}s)"
        )


class ResourceLimiter:
    """
    Enforces memory, CPU, and timeout limits for operations.

    Usage:
        limiter = ResourceLimiter(max_memory_gb=4, timeout_seconds=600)

        @limiter.limit()
        async def analyze_binary(file_path: str):
            # This function is now protected by resource limits
            ...
    """

    def __init__(self, limits: Optional[ResourceLimits] = None):
        self.limits = limits or ResourceLimits()
        self.process = psutil.Process()
        self._monitoring = False
        self._start_time: Optional[float] = None

    def get_current_usage(self) -> ResourceUsage:
        """Get current resource usage"""
        memory_info = self.process.memory_info()
        memory_mb = memory_info.rss / (1024 * 1024)
        memory_percent = self.process.memory_percent()
        cpu_percent = self.process.cpu_percent(interval=0.1)
        elapsed = time.time() - self._start_time if self._start_time else 0

        return ResourceUsage(
            memory_mb=memory_mb,
            memory_percent=memory_percent,
            cpu_percent=cpu_percent,
            elapsed_seconds=elapsed,
            pid=self.process.pid
        )

    def check_limits(self, usage: ResourceUsage) -> None:
        """
        Check if current usage exceeds limits.
        Raises ResourceLimitExceeded or TimeoutExceeded if limits exceeded.
        """
        # Check memory limit (both absolute and percentage)
        max_memory_mb = self.limits.max_memory_gb * 1024
        if usage.memory_mb > max_memory_mb:
            raise ResourceLimitExceeded("memory_mb", usage.memory_mb, max_memory_mb)

        if usage.memory_percent > self.limits.max_memory_percent:
            raise ResourceLimitExceeded(
                "memory_percent", usage.memory_percent, self.limits.max_memory_percent
            )

        # Check CPU limit
        if usage.cpu_percent > self.limits.max_cpu_percent:
            logger.warning(
                f"High CPU usage: {usage.cpu_percent:.1f}% (limit: {self.limits.max_cpu_percent}%)"
            )
            # Note: We warn but don't kill on CPU - just memory and timeout

        # Check timeout
        if usage.elapsed_seconds > self.limits.timeout_seconds:
            raise TimeoutExceeded(usage.elapsed_seconds, self.limits.timeout_seconds)

    async def monitor_loop(self, stop_event: asyncio.Event) -> None:
        """Background monitoring loop"""
        self._monitoring = True

        while not stop_event.is_set():
            try:
                usage = self.get_current_usage()
                self.check_limits(usage)

                # Log usage every minute
                if int(usage.elapsed_seconds) % 60 == 0:
                    logger.info(
                        f"Resource usage: {usage.memory_mb:.1f}MB ({usage.memory_percent:.1f}%), "
                        f"CPU: {usage.cpu_percent:.1f}%, Time: {usage.elapsed_seconds:.0f}s"
                    )

                await asyncio.sleep(self.limits.check_interval_seconds)

            except (ResourceLimitExceeded, TimeoutExceeded):
                self._monitoring = False
                raise
            except Exception as e:
                logger.error(f"Error in resource monitor: {e}")
                await asyncio.sleep(self.limits.check_interval_seconds)

        self._monitoring = False

    @asynccontextmanager
    async def monitor(self):
        """
        Context manager for resource monitoring.

        Usage:
            async with limiter.monitor():
                # Protected operation
                await expensive_operation()
        """
        self._start_time = time.time()
        stop_event = asyncio.Event()
        monitor_task = asyncio.create_task(self.monitor_loop(stop_event))

        try:
            yield self
        finally:
            stop_event.set()
            try:
                await asyncio.wait_for(monitor_task, timeout=5.0)
            except asyncio.TimeoutError:
                monitor_task.cancel()

            # Log final usage
            final_usage = self.get_current_usage()
            logger.info(
                f"Operation completed: {final_usage.memory_mb:.1f}MB peak, "
                f"{final_usage.elapsed_seconds:.1f}s elapsed"
            )

    def limit(
        self,
        max_memory_gb: Optional[float] = None,
        timeout_seconds: Optional[int] = None
    ):
        """
        Decorator to add resource limits to async functions.

        Usage:
            @limiter.limit(max_memory_gb=2, timeout_seconds=300)
            async def analyze_file(path: str):
                ...
        """
        def decorator(func: Callable) -> Callable:
            @wraps(func)
            async def wrapper(*args, **kwargs) -> Any:
                # Create custom limits if specified
                limits = ResourceLimits(
                    max_memory_gb=max_memory_gb or self.limits.max_memory_gb,
                    max_memory_percent=self.limits.max_memory_percent,
                    max_cpu_percent=self.limits.max_cpu_percent,
                    timeout_seconds=timeout_seconds or self.limits.timeout_seconds,
                    check_interval_seconds=self.limits.check_interval_seconds
                )

                limiter = ResourceLimiter(limits)

                try:
                    async with limiter.monitor():
                        result = await func(*args, **kwargs)
                        return result

                except ResourceLimitExceeded as e:
                    logger.error(f"Resource limit exceeded in {func.__name__}: {e}")
                    raise
                except TimeoutExceeded as e:
                    logger.error(f"Timeout exceeded in {func.__name__}: {e}")
                    raise
                except Exception as e:
                    logger.error(f"Error in {func.__name__}: {e}", exc_info=True)
                    raise

            return wrapper
        return decorator


# Global limiter instance with production defaults
default_limiter = ResourceLimiter(
    limits=ResourceLimits(
        max_memory_gb=8.0,        # 8GB max per operation
        max_memory_percent=80.0,  # 80% of system memory
        max_cpu_percent=80.0,     # 80% CPU (warning only)
        timeout_seconds=3600,     # 1 hour timeout
        check_interval_seconds=5.0
    )
)


# Convenience decorators with preset limits
def limit_small(func: Callable) -> Callable:
    """Small operation: 2GB, 5 minutes"""
    return default_limiter.limit(max_memory_gb=2.0, timeout_seconds=300)(func)


def limit_medium(func: Callable) -> Callable:
    """Medium operation: 4GB, 15 minutes"""
    return default_limiter.limit(max_memory_gb=4.0, timeout_seconds=900)(func)


def limit_large(func: Callable) -> Callable:
    """Large operation: 8GB, 1 hour"""
    return default_limiter.limit(max_memory_gb=8.0, timeout_seconds=3600)(func)


def limit_xlarge(func: Callable) -> Callable:
    """Extra large operation: 16GB, 2 hours"""
    return default_limiter.limit(max_memory_gb=16.0, timeout_seconds=7200)(func)


# System-wide resource checker
class SystemResourceChecker:
    """Check if system has enough resources before starting operations"""

    @staticmethod
    def check_available_memory(required_gb: float) -> bool:
        """Check if system has enough free memory"""
        memory = psutil.virtual_memory()
        available_gb = memory.available / (1024 ** 3)
        return available_gb >= required_gb

    @staticmethod
    def check_available_disk(path: str, required_gb: float) -> bool:
        """Check if disk has enough free space"""
        disk = psutil.disk_usage(path)
        available_gb = disk.free / (1024 ** 3)
        return available_gb >= required_gb

    @staticmethod
    def get_system_stats() -> dict:
        """Get overall system resource statistics"""
        memory = psutil.virtual_memory()
        disk = psutil.disk_usage('/')
        cpu_percent = psutil.cpu_percent(interval=1)

        return {
            "memory": {
                "total_gb": memory.total / (1024 ** 3),
                "available_gb": memory.available / (1024 ** 3),
                "used_percent": memory.percent,
                "free_percent": 100 - memory.percent
            },
            "disk": {
                "total_gb": disk.total / (1024 ** 3),
                "free_gb": disk.free / (1024 ** 3),
                "used_percent": disk.percent,
                "free_percent": 100 - disk.percent
            },
            "cpu": {
                "percent": cpu_percent,
                "count": psutil.cpu_count()
            },
            "load_average": psutil.getloadavg() if hasattr(psutil, 'getloadavg') else None
        }

    @staticmethod
    def can_accept_operation(required_memory_gb: float = 2.0) -> tuple[bool, str]:
        """
        Check if system can accept a new operation.
        Returns (can_accept, reason)
        """
        stats = SystemResourceChecker.get_system_stats()

        # Check memory
        if stats["memory"]["free_percent"] < 20:
            return False, "System memory critically low (<20% free)"

        if stats["memory"]["available_gb"] < required_memory_gb:
            return False, f"Insufficient memory: need {required_memory_gb}GB, have {stats['memory']['available_gb']:.1f}GB"

        # Check disk
        if stats["disk"]["free_percent"] < 10:
            return False, "Disk space critically low (<10% free)"

        # Check CPU load
        if stats["cpu"]["percent"] > 95:
            return False, "System CPU critically high (>95%)"

        return True, "OK"
