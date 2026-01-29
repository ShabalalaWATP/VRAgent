from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
import os

from backend.core.config import settings
from backend.core.database import Base, engine
from backend.core.exceptions import VRAgentError
from backend.core.logging import get_logger
from backend.core.security_middleware import SecurityHeadersMiddleware
from backend.routers import projects, scans, reports, exports, exploitability, websocket, webhooks, pcap, network, dns, traceroute, api_tester, fuzzing, mitm, vulnhuntr, auth, admin, agentic_scan, findings, reverse_engineering, learn_chat, social, chat_websocket, project_files, kanban, compliance, ai_analysis, fuzzer_reports, interactive_replay, agentic_fuzzer, whiteboard, whiteboard_ws, notes_websocket, kanban_ws, combined_analysis, api_collections, zap, coverage, dynamic_scan, protocol_network, agentic_binary, android_fuzzer, jwt_security, malware_analysis, unified_binary_scanner, health, secure_files
from backend import models  # noqa: F401  # ensure models are registered

logger = get_logger(__name__)

# Create tables for demo; in production use Alembic migrations only.
if settings.environment == "development":
    Base.metadata.create_all(bind=engine)

# Enable rate limiting (defaults to true in production, false in development)
_rate_limit_default = "false" if settings.environment == "development" else "true"
ENABLE_RATE_LIMITING = os.getenv("ENABLE_RATE_LIMITING", _rate_limit_default).lower() == "true"

app = FastAPI(
    title="AI Agent Vulnerability Research API",
    version="0.1.0",
    description="API for scanning code projects for security vulnerabilities",
    docs_url="/docs" if settings.environment != "production" else None,
    redoc_url="/redoc" if settings.environment != "production" else None,
)

# Configure CORS
# In development, allow all origins for flexibility (local network access, etc.)
# In production, restrict to specific origins via CORS_ORIGINS env var
cors_origins_env = os.getenv("CORS_ORIGINS", "")

if cors_origins_env:
    # Explicit origins configured - use them in any environment
    allowed_origins = [origin.strip() for origin in cors_origins_env.split(",") if origin.strip()]
    app.add_middleware(
        CORSMiddleware,
        allow_origins=allowed_origins,
        allow_credentials=True,
        allow_methods=["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"],
        allow_headers=["Authorization", "Content-Type", "X-Requested-With"],
    )
elif settings.environment == "development":
    # Development: allow localhost origins only (use CORS_ORIGINS for LAN access)
    app.add_middleware(
        CORSMiddleware,
        allow_origins=[
            "http://localhost:5173",
            "http://localhost:3000",
            "http://localhost:8080",
            "http://127.0.0.1:5173",
            "http://127.0.0.1:3000",
            "http://127.0.0.1:8080",
        ],
        allow_credentials=True,
        allow_methods=["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"],
        allow_headers=["Authorization", "Content-Type", "X-Requested-With"],
    )
else:
    # Production without CORS_ORIGINS: restrict to common localhost ports
    logger.warning(
        "CORS_ORIGINS not configured for production. "
        "Set CORS_ORIGINS environment variable for proper security."
    )
    app.add_middleware(
        CORSMiddleware,
        allow_origins=[
            "http://localhost:5173",
            "http://localhost:3000",
            "http://127.0.0.1:5173",
            "http://127.0.0.1:3000",
        ],
        allow_credentials=True,
        allow_methods=["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"],
        allow_headers=["Authorization", "Content-Type", "X-Requested-With"],
    )

# Add security headers middleware (runs after CORS)
app.add_middleware(SecurityHeadersMiddleware)

# Add rate limiting middleware in production
if ENABLE_RATE_LIMITING:
    from backend.core.rate_limit import RateLimitMiddleware
    app.add_middleware(RateLimitMiddleware, default_limit=100, window_seconds=60)
    logger.info("Rate limiting middleware enabled")


# Global exception handlers
@app.exception_handler(VRAgentError)
async def vragent_exception_handler(request: Request, exc: VRAgentError):
    """Handle custom VRAgent exceptions with structured response."""
    logger.warning(f"VRAgent error: {exc.error_code} - {exc.message}", extra=exc.details)
    return JSONResponse(
        status_code=404 if exc.error_code.endswith("NOT_FOUND") else 422,
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


app.include_router(auth.router, tags=["authentication"])
app.include_router(admin.router, tags=["admin"])
app.include_router(health.router, tags=["health"])
app.include_router(projects.router, prefix="/projects", tags=["projects"])
app.include_router(scans.router, prefix="/projects", tags=["scans"])
app.include_router(reports.router, prefix="/projects/{project_id}/reports", tags=["reports"])
app.include_router(reports.global_router, prefix="/reports", tags=["reports-global"])  # For /recent endpoint
app.include_router(exports.router, prefix="/reports", tags=["exports"])
app.include_router(exploitability.router, prefix="/reports", tags=["exploitability"])
app.include_router(webhooks.router, prefix="/projects", tags=["webhooks"])
app.include_router(websocket.router, tags=["websocket"])
app.include_router(pcap.router, tags=["pcap"])
app.include_router(network.router, tags=["network-analysis"])
app.include_router(dns.router, tags=["dns-reconnaissance"])
app.include_router(traceroute.router, tags=["traceroute-visualization"])
app.include_router(api_tester.router, tags=["api-tester"])
app.include_router(fuzzing.router, tags=["security-fuzzer"])
app.include_router(mitm.router, tags=["mitm-workbench"])
app.include_router(vulnhuntr.router, tags=["vulnhuntr"])
app.include_router(agentic_scan.router, tags=["agentic-ai-scan"])
app.include_router(findings.router, tags=["findings"])
app.include_router(reverse_engineering.router, tags=["reverse-engineering"])
app.include_router(learn_chat.router, tags=["learn-chat"])
app.include_router(social.router, tags=["social"])
app.include_router(chat_websocket.router, tags=["chat-websocket"])
app.include_router(project_files.router, tags=["project-files"])
app.include_router(kanban.router, tags=["kanban"])
app.include_router(agentic_fuzzer.router, tags=["agentic-fuzzer"])
app.include_router(compliance.router, tags=["compliance-cve"])
app.include_router(ai_analysis.router, tags=["ai-security-analysis"])
app.include_router(fuzzer_reports.router, tags=["fuzzer-reports"])
app.include_router(interactive_replay.router, tags=["interactive-fuzzing"])
app.include_router(whiteboard.router, tags=["whiteboard"])
app.include_router(whiteboard_ws.router, tags=["whiteboard-websocket"])
app.include_router(notes_websocket.router, tags=["notes-websocket"])
app.include_router(kanban_ws.router, tags=["kanban-websocket"])
app.include_router(combined_analysis.router, prefix="/combined-analysis", tags=["combined-analysis"])
app.include_router(api_collections.router, tags=["api-collections"])
app.include_router(zap.router, tags=["owasp-zap"])
app.include_router(coverage.router, tags=["coverage-analysis"])
app.include_router(dynamic_scan.router, tags=["dynamic-security-scanner"])
app.include_router(protocol_network.router, tags=["protocol-fuzzer"])
app.include_router(agentic_binary.router, tags=["agentic-binary-fuzzer"])
app.include_router(android_fuzzer.router, tags=["android-fuzzer"])
app.include_router(jwt_security.router, tags=["jwt-security"])
app.include_router(malware_analysis.router, tags=["malware-analysis"])
app.include_router(unified_binary_scanner.router, tags=["unified-binary-scanner"])

# Secure file download endpoints (with authentication and authorization)
app.include_router(secure_files.router, tags=["secure-files"])

# Create upload directories (files are served via secure_files router, not StaticFiles)
# SECURITY: Do NOT use StaticFiles for user uploads - it bypasses authentication!
import os
CHAT_UPLOAD_DIR = os.path.join(settings.upload_dir, "chat")
os.makedirs(CHAT_UPLOAD_DIR, exist_ok=True)
PROJECT_FILES_DIR = os.path.join(settings.upload_dir, "project_files")
os.makedirs(PROJECT_FILES_DIR, exist_ok=True)
PROJECT_DOCS_DIR = os.path.join(settings.upload_dir, "project_documents")
os.makedirs(PROJECT_DOCS_DIR, exist_ok=True)


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
    
    # Check OWASP ZAP
    try:
        from backend.services.zap_service import zap_health_check
        import asyncio
        zap_health = asyncio.get_event_loop().run_until_complete(zap_health_check())
        if zap_health.get("available"):
            health_status["services"]["zap"] = {"status": "available", "version": zap_health.get("version")}
        else:
            health_status["services"]["zap"] = {"status": "unavailable", "error": zap_health.get("error")}
    except Exception as e:
        health_status["services"]["zap"] = {"status": "error", "message": str(e)}
    
    # Check Offline Data Availability
    try:
        from backend.services.nvd_service import get_local_db_stats
        from backend.services.exploit_db_service import get_offline_status
        
        # NVD local database
        nvd_stats = get_local_db_stats()
        health_status["services"]["nvd_offline"] = {
            "status": "available" if nvd_stats.get("available") else "not_synced",
            **nvd_stats
        }
        
        # Exploit databases (ExploitDB + Nuclei)
        exploit_status = get_offline_status()
        health_status["services"]["exploit_db_offline"] = {
            "status": "available" if exploit_status.get("exploitdb_available") or exploit_status.get("nuclei_available") else "not_synced",
            **exploit_status
        }
    except Exception as e:
        health_status["services"]["offline_data"] = {"status": "error", "message": str(e)}
    
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
    import asyncio
    logger.info(f"VRAgent API starting in {settings.environment} mode")

    # Check database connectivity on startup
    try:
        from backend.core.database import SessionLocal
        from backend.services.auth_service import count_users

        db = SessionLocal()
        try:
            user_count = count_users(db)
            if user_count == 0:
                logger.info("No users found. Register your first admin account via the UI.")
        finally:
            db.close()
    except Exception as e:
        logger.error(f"Database connectivity check failed: {e}")

    # Start Redis pub/sub subscriber for WebSocket progress updates
    from backend.services.websocket_service import progress_manager
    await progress_manager.start_subscriber()
    logger.info("Started Redis pub/sub subscriber for scan progress")
    
    # Start reverse engineering cleanup background tasks
    from backend.routers.reverse_engineering import (
        cleanup_old_jadx_cache,
        cleanup_old_notes_storage,
        cleanup_orphaned_temp_dirs,
        cleanup_stale_scan_sessions,
    )
    asyncio.create_task(cleanup_old_jadx_cache())
    asyncio.create_task(cleanup_old_notes_storage())
    asyncio.create_task(cleanup_stale_scan_sessions())
    logger.info("Started reverse engineering cleanup background tasks")
    
    # Clean orphaned temp directories from previous sessions on startup
    await cleanup_orphaned_temp_dirs()
    logger.info("Cleaned up orphaned temp directories from previous sessions")


@app.on_event("shutdown")
async def shutdown_event():
    """Log application shutdown and cleanup."""
    logger.info("VRAgent API shutting down")
    
    # Stop Redis pub/sub subscriber
    from backend.services.websocket_service import progress_manager
    await progress_manager.stop_subscriber()
    logger.info("Stopped Redis pub/sub subscriber")
