from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from backend.core.config import settings
from backend.core.database import Base, engine
from backend.core.exceptions import VRAgentError
from backend.core.logging import get_logger
from backend.routers import projects, scans, reports, exports, exploitability, websocket, webhooks, pcap, network, dns, traceroute, api_tester
from backend import models  # noqa: F401  # ensure models are registered

logger = get_logger(__name__)

# Create tables for demo; in production use Alembic migrations only.
if settings.environment == "development":
    Base.metadata.create_all(bind=engine)

app = FastAPI(
    title="AI Agent Vulnerability Research API",
    version="0.1.0",
    description="API for scanning code projects for security vulnerabilities",
    docs_url="/docs" if settings.environment != "production" else None,
    redoc_url="/redoc" if settings.environment != "production" else None,
)

# Configure CORS - restrict in production
allowed_origins = ["*"] if settings.environment == "development" else [
    "http://localhost:5173",
    "http://localhost:3000",
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=allowed_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# Global exception handlers
@app.exception_handler(VRAgentError)
async def vragent_exception_handler(request: Request, exc: VRAgentError):
    """Handle custom VRAgent exceptions with structured response."""
    logger.warning(f"VRAgent error: {exc.error_code} - {exc.message}", extra=exc.details)
    return JSONResponse(
        status_code=400 if exc.error_code.endswith("NOT_FOUND") else 422,
        content={
            "error": exc.error_code,
            "message": exc.message,
            "details": exc.details,
        },
    )


@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    """Catch-all handler for unhandled exceptions."""
    logger.exception(f"Unhandled exception on {request.method} {request.url.path}: {exc}")
    return JSONResponse(
        status_code=500,
        content={
            "error": "INTERNAL_SERVER_ERROR",
            "message": "An unexpected error occurred" if settings.environment == "production" else str(exc),
        },
    )


app.include_router(projects.router, prefix="/projects", tags=["projects"])
app.include_router(scans.router, prefix="/projects", tags=["scans"])
app.include_router(reports.router, prefix="/projects/{project_id}/reports", tags=["reports"])
app.include_router(exports.router, prefix="/reports", tags=["exports"])
app.include_router(exploitability.router, prefix="/reports", tags=["exploitability"])
app.include_router(webhooks.router, prefix="/projects", tags=["webhooks"])
app.include_router(websocket.router, tags=["websocket"])
app.include_router(pcap.router, tags=["pcap"])
app.include_router(network.router, tags=["network-analysis"])
app.include_router(dns.router, tags=["dns-reconnaissance"])
app.include_router(traceroute.router, tags=["traceroute-visualization"])
app.include_router(api_tester.router, tags=["api-tester"])


@app.get("/health")
def health():
    """Basic health check endpoint."""
    return {"status": "ok", "environment": settings.environment}


@app.get("/health/detailed")
def health_detailed():
    """
    Detailed health check that verifies all service connections.
    Use this for monitoring and debugging.
    """
    from redis import Redis
    from sqlalchemy import text
    from backend.core.database import engine
    from backend.core.cache import cache
    
    health_status = {
        "status": "ok",
        "environment": settings.environment,
        "services": {}
    }
    
    # Check database
    try:
        with engine.connect() as conn:
            conn.execute(text("SELECT 1"))
        health_status["services"]["database"] = {"status": "ok"}
    except Exception as e:
        health_status["services"]["database"] = {"status": "error", "message": str(e)}
        health_status["status"] = "degraded"
    
    # Check Redis and cache
    try:
        redis_client = Redis.from_url(settings.redis_url)
        redis_client.ping()
        health_status["services"]["redis"] = {"status": "ok"}
        
        # Get cache stats
        cache_stats = cache.get_stats()
        health_status["services"]["cache"] = cache_stats
    except Exception as e:
        health_status["services"]["redis"] = {"status": "error", "message": str(e)}
        health_status["services"]["cache"] = {"status": "unavailable"}
        health_status["status"] = "degraded"
    
    # Check Gemini API (optional)
    if settings.gemini_api_key:
        health_status["services"]["gemini"] = {"status": "configured"}
    else:
        health_status["services"]["gemini"] = {"status": "not_configured", "message": "Running without AI features"}
    
    # Check Semgrep (optional)
    from backend.services.semgrep_service import is_semgrep_available
    if is_semgrep_available():
        health_status["services"]["semgrep"] = {"status": "available"}
    else:
        health_status["services"]["semgrep"] = {"status": "not_installed", "message": "Deep static analysis unavailable"}
    
    return health_status


@app.get("/cache/stats")
def cache_stats():
    """
    Get detailed cache statistics.
    Shows Redis cache hit rates, memory usage, and keys by namespace.
    """
    from backend.core.cache import cache
    return cache.get_stats()


@app.delete("/cache/{namespace}")
def clear_cache_namespace(namespace: str):
    """
    Clear all cached data in a specific namespace.
    
    Namespaces:
    - osv: CVE/vulnerability lookups from OSV.dev
    - nvd: NVD enrichment data
    - epss: EPSS exploitation scores
    - embedding: Code embeddings
    """
    from backend.core.cache import cache
    
    valid_namespaces = ["osv", "nvd", "epss", "embedding"]
    if namespace not in valid_namespaces:
        return {"error": f"Invalid namespace. Valid options: {valid_namespaces}"}
    
    count = cache.clear_namespace(namespace)
    return {"message": f"Cleared {count} keys from {namespace} cache"}


@app.on_event("startup")
async def startup_event():
    """Log application startup and start background services."""
    logger.info(f"VRAgent API starting in {settings.environment} mode")
    
    # Start Redis pub/sub subscriber for WebSocket progress updates
    from backend.services.websocket_service import progress_manager
    await progress_manager.start_subscriber()
    logger.info("Started Redis pub/sub subscriber for scan progress")


@app.on_event("shutdown")
async def shutdown_event():
    """Log application shutdown and cleanup."""
    logger.info("VRAgent API shutting down")
    
    # Stop Redis pub/sub subscriber
    from backend.services.websocket_service import progress_manager
    await progress_manager.stop_subscriber()
    logger.info("Stopped Redis pub/sub subscriber")
