"""
VRAgent Health Check Endpoint
Monitors system health, dependencies, and resource availability
"""

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from typing import Optional, Dict, Any
from datetime import datetime
import logging
import asyncio
import psutil

from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import text

from backend.core.database import get_db
from backend.core.resource_limits import SystemResourceChecker

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/health", tags=["Health"])


class ServiceStatus(BaseModel):
    """Status of individual service"""
    name: str
    status: str  # ok, degraded, down
    latency_ms: Optional[float] = None
    error: Optional[str] = None
    details: Optional[Dict[str, Any]] = None


class HealthResponse(BaseModel):
    """Overall health check response"""
    status: str  # healthy, degraded, unhealthy
    timestamp: datetime
    version: str
    uptime_seconds: float
    services: Dict[str, ServiceStatus]
    resources: Dict[str, Any]
    warnings: list[str] = []


# Track startup time
import time
STARTUP_TIME = time.time()


async def check_database(db: AsyncSession = None) -> ServiceStatus:
    """Check PostgreSQL database connectivity"""
    start = time.time()
    try:
        # Use synchronous database connection (wrapped for async compatibility)
        from backend.core.database import SessionLocal

        def _check_db():
            with SessionLocal() as session:
                result = session.execute(text("SELECT 1"))
                result.fetchone()
                # Check pgvector extension
                try:
                    result = session.execute(text("SELECT extname FROM pg_extension WHERE extname='vector'"))
                    has_vector = result.fetchone() is not None
                    return {"connection": "ok", "pgvector": "available" if has_vector else "not_installed"}
                except Exception as e:
                    return {"connection": "ok", "pgvector": "unknown", "warning": str(e)}

        details = await asyncio.to_thread(_check_db)
        latency_ms = (time.time() - start) * 1000
        return ServiceStatus(name="database", status="ok", latency_ms=latency_ms, details=details)

    except Exception as e:
        logger.error(f"Database health check failed: {e}")
        return ServiceStatus(
            name="database",
            status="down",
            error=str(e)
        )


async def _legacy_check_database(db: AsyncSession = None) -> ServiceStatus:
    """Legacy async database check - kept for reference"""
    start = time.time()
    try:
        if db is None:
            return ServiceStatus(name="database", status="down", error="No db session provided")

        # Simple query to test connection
        result = await db.execute(text("SELECT 1"))
        result.fetchone()

        latency_ms = (time.time() - start) * 1000

        # Additional checks
        try:
            # Check if pgvector extension is available
            result = await db.execute(text("SELECT extname FROM pg_extension WHERE extname='vector'"))
            has_vector = result.fetchone() is not None

            details = {
                "connection": "ok",
                "pgvector": "available" if has_vector else "not_installed"
            }
        except Exception as e:
            details = {"connection": "ok", "pgvector": "unknown", "warning": str(e)}

        return ServiceStatus(
            name="database",
            status="ok",
            latency_ms=latency_ms,
            details=details
        )

    except Exception as e:
        logger.error(f"Database health check failed: {e}")
        return ServiceStatus(
            name="database",
            status="down",
            error=str(e)
        )


async def check_redis() -> ServiceStatus:
    """Check Redis connectivity"""
    start = time.time()
    try:
        import redis.asyncio as aioredis
        from backend.core.config import settings

        # Parse Redis URL
        redis_client = aioredis.from_url(
            settings.redis_url,
            encoding="utf-8",
            decode_responses=True
        )

        # Ping Redis
        await redis_client.ping()
        latency_ms = (time.time() - start) * 1000

        # Get Redis info
        info = await redis_client.info()
        await redis_client.close()

        return ServiceStatus(
            name="redis",
            status="ok",
            latency_ms=latency_ms,
            details={
                "version": info.get("redis_version", "unknown"),
                "uptime_days": info.get("uptime_in_days", 0),
                "connected_clients": info.get("connected_clients", 0)
            }
        )

    except ImportError:
        return ServiceStatus(
            name="redis",
            status="degraded",
            error="redis package not installed"
        )
    except Exception as e:
        logger.error(f"Redis health check failed: {e}")
        return ServiceStatus(
            name="redis",
            status="down",
            error=str(e)
        )


async def check_ai_services() -> ServiceStatus:
    """Check AI service availability (Gemini/OpenAI)"""
    try:
        from backend.core.config import settings

        available_services = []
        if settings.gemini_api_key:
            available_services.append("gemini")
        if settings.openai_api_key:
            available_services.append("openai")

        if not available_services:
            return ServiceStatus(
                name="ai_services",
                status="degraded",
                error="No AI API keys configured",
                details={"available": []}
            )

        return ServiceStatus(
            name="ai_services",
            status="ok",
            details={"available": available_services}
        )

    except Exception as e:
        logger.error(f"AI services check failed: {e}")
        return ServiceStatus(
            name="ai_services",
            status="degraded",
            error=str(e)
        )


async def check_ghidra() -> ServiceStatus:
    """Check Ghidra availability"""
    try:
        from backend.core.config import settings
        import os

        ghidra_home = settings.ghidra_home
        if not ghidra_home:
            return ServiceStatus(
                name="ghidra",
                status="degraded",
                error="GHIDRA_HOME not configured"
            )

        # Check if Ghidra directory exists
        if not os.path.isdir(ghidra_home):
            return ServiceStatus(
                name="ghidra",
                status="degraded",
                error=f"GHIDRA_HOME directory not found: {ghidra_home}"
            )

        # Check for analyzeHeadless script
        analyze_script = os.path.join(ghidra_home, "support", "analyzeHeadless")
        if os.name == 'nt':
            analyze_script += ".bat"

        if not os.path.isfile(analyze_script):
            return ServiceStatus(
                name="ghidra",
                status="degraded",
                error="analyzeHeadless script not found"
            )

        return ServiceStatus(
            name="ghidra",
            status="ok",
            details={"ghidra_home": ghidra_home}
        )

    except Exception as e:
        logger.error(f"Ghidra check failed: {e}")
        return ServiceStatus(
            name="ghidra",
            status="degraded",
            error=str(e)
        )


def get_resource_status() -> Dict[str, Any]:
    """Get current system resource status"""
    stats = SystemResourceChecker.get_system_stats()

    # Add warnings for critical resource levels
    warnings = []
    if stats["memory"]["free_percent"] < 20:
        warnings.append(f"Low memory: {stats['memory']['free_percent']:.1f}% free")

    if stats["disk"]["free_percent"] < 10:
        warnings.append(f"Low disk space: {stats['disk']['free_percent']:.1f}% free")

    if stats["cpu"]["percent"] > 90:
        warnings.append(f"High CPU usage: {stats['cpu']['percent']:.1f}%")

    stats["warnings"] = warnings
    return stats


@router.get("", response_model=HealthResponse)
async def health_check():
    """
    Comprehensive health check endpoint.

    Returns system health status, service availability, and resource usage.
    Used by:
    - Load balancers for routing decisions
    - Monitoring systems (Prometheus, etc.)
    - Docker health checks
    - Manual diagnostics
    """
    try:
        # Check all services in parallel
        db_task = check_database(None)
        redis_task = check_redis()
        ai_task = check_ai_services()
        ghidra_task = check_ghidra()

        # Gather results
        tasks = [db_task, redis_task, ai_task, ghidra_task]
        service_results = await asyncio.gather(*tasks, return_exceptions=True)

        # Build services dict
        services = {}
        for result in service_results:
            if isinstance(result, ServiceStatus):
                services[result.name] = result
            elif isinstance(result, Exception):
                logger.error(f"Service check failed: {result}")

        # Get resource status
        resources = get_resource_status()

        # Determine overall status
        service_statuses = [s.status for s in services.values()]
        if all(s == "ok" for s in service_statuses):
            overall_status = "healthy"
        elif any(s == "down" for s in service_statuses):
            overall_status = "unhealthy"
        else:
            overall_status = "degraded"

        # Collect warnings
        warnings = resources.get("warnings", [])

        # Add service warnings
        for service in services.values():
            if service.status == "degraded" and service.error:
                warnings.append(f"{service.name}: {service.error}")

        # Calculate uptime
        uptime_seconds = time.time() - STARTUP_TIME

        return HealthResponse(
            status=overall_status,
            timestamp=datetime.utcnow(),
            version="1.0.0",  # TODO: Get from config or git tag
            uptime_seconds=uptime_seconds,
            services=services,
            resources=resources,
            warnings=warnings
        )

    except Exception as e:
        logger.error(f"Health check failed: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Health check failed: {str(e)}")


@router.get("/ready")
async def readiness_check():
    """
    Kubernetes-style readiness probe.
    Returns 200 if service is ready to accept traffic, 503 otherwise.
    """
    try:
        # Check critical services only
        db_status = await check_database(None)
        if db_status.status == "down":
            raise HTTPException(status_code=503, detail="Database not ready")

        redis_status = await check_redis()
        if redis_status.status == "down":
            raise HTTPException(status_code=503, detail="Redis not ready")

        # Check if system can accept operations
        can_accept, reason = SystemResourceChecker.can_accept_operation()
        if not can_accept:
            raise HTTPException(status_code=503, detail=f"System overloaded: {reason}")

        return {"status": "ready"}

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Readiness check failed: {e}")
        raise HTTPException(status_code=503, detail=f"Not ready: {str(e)}")


@router.get("/live")
async def liveness_check():
    """
    Kubernetes-style liveness probe.
    Returns 200 if service is alive, 500 otherwise.
    Simple check - just verify the service responds.
    """
    return {"status": "alive", "timestamp": datetime.utcnow()}


@router.get("/resources")
async def resources_status():
    """
    Detailed resource usage endpoint.
    For monitoring and capacity planning.
    """
    try:
        stats = SystemResourceChecker.get_system_stats()

        # Add process-specific stats
        process = psutil.Process()
        process_stats = {
            "pid": process.pid,
            "memory_mb": process.memory_info().rss / (1024 * 1024),
            "memory_percent": process.memory_percent(),
            "cpu_percent": process.cpu_percent(interval=0.1),
            "threads": process.num_threads(),
            "open_files": len(process.open_files()),
            "connections": len(process.connections())
        }

        return {
            "system": stats,
            "process": process_stats,
            "timestamp": datetime.utcnow()
        }

    except Exception as e:
        logger.error(f"Resource status check failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/version")
async def version_info():
    """Get VRAgent version information"""
    try:
        # Try to get git commit info
        import subprocess
        try:
            commit = subprocess.check_output(
                ["git", "rev-parse", "--short", "HEAD"],
                stderr=subprocess.DEVNULL
            ).decode().strip()

            branch = subprocess.check_output(
                ["git", "rev-parse", "--abbrev-ref", "HEAD"],
                stderr=subprocess.DEVNULL
            ).decode().strip()

            git_info = {"commit": commit, "branch": branch}
        except:
            git_info = None

        return {
            "version": "1.0.0",
            "name": "VRAgent Binary Analyzer",
            "git": git_info,
            "python_version": f"{psutil.sys.version_info.major}.{psutil.sys.version_info.minor}.{psutil.sys.version_info.micro}"
        }

    except Exception as e:
        logger.error(f"Version check failed: {e}")
        return {"version": "unknown", "error": str(e)}


@router.get("/metrics")
async def prometheus_metrics():
    """
    Prometheus metrics endpoint.
    Returns metrics in Prometheus text format.

    Used by Prometheus scraper for monitoring.
    """
    try:
        from backend.core.prometheus_metrics import get_metrics, get_content_type
        from fastapi.responses import Response

        metrics = get_metrics()
        return Response(
            content=metrics,
            media_type=get_content_type()
        )

    except ImportError:
        # Prometheus client not installed
        raise HTTPException(
            status_code=503,
            detail="Prometheus metrics not available (prometheus_client not installed)"
        )
