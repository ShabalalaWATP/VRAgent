"""
Coverage API Router - Endpoints for coverage visualization and analysis.

Provides:
- Coverage heatmap generation (SVG/JSON)
- Coverage timeline and trend analysis
- Module/function coverage breakdown
- Coverage gap analysis
- Corpus coverage analysis
- QEMU coverage extraction
- Export functionality (JSON, HTML, CSV)
"""

import os
import hashlib
from typing import Any, Dict, List, Optional
from fastapi import APIRouter, HTTPException, Query, Response, UploadFile, File, WebSocket, Depends
from backend.core.auth import get_current_active_user
from backend.models.models import User
from fastapi.responses import HTMLResponse, PlainTextResponse
from pydantic import BaseModel, Field

# Import services
try:
    from ..services.coverage_visualization_service import (
        CoverageVisualizationService,
        CoverageHeatmapConfig,
        CoverageHeatmapData,
        CoverageTrendData,
        CoverageGapAnalysis,
        ModuleCoverageBreakdown,
        create_visualization_service,
        generate_coverage_dashboard,
    )
    VISUALIZATION_AVAILABLE = True
except ImportError:
    VISUALIZATION_AVAILABLE = False

try:
    from ..services.qemu_coverage_service import (
        QemuCoverageProvider,
        QemuCoverageConfig,
        QemuCoverageResult,
        check_qemu_coverage_availability,
        create_qemu_coverage_provider,
    )
    from ..services.binary_fuzzer_service import QemuArchitecture
    QEMU_AVAILABLE = True
except ImportError:
    QEMU_AVAILABLE = False

try:
    from ..services.afl_telemetry_service import load_summary
    TELEMETRY_AVAILABLE = True
except ImportError:
    TELEMETRY_AVAILABLE = False


router = APIRouter(prefix="/coverage", tags=["Coverage"])


# ============================================================================
# Request/Response Models
# ============================================================================


class HeatmapRequest(BaseModel):
    """Request for heatmap generation."""
    width: int = Field(default=256, ge=32, le=1024)
    height: int = Field(default=256, ge=32, le=1024)
    color_scheme: str = Field(default="viridis")
    log_scale: bool = Field(default=True)
    include_annotations: bool = Field(default=True)


class TimelineRequest(BaseModel):
    """Request for timeline data."""
    max_points: int = Field(default=500, ge=10, le=5000)
    start_time: Optional[float] = None
    end_time: Optional[float] = None


class QemuTraceRequest(BaseModel):
    """Request for QEMU coverage trace."""
    target_path: str
    architecture: Optional[str] = None
    compcov_level: int = Field(default=0, ge=0, le=2)
    timeout_ms: int = Field(default=5000, ge=100, le=60000)


class CorpusCompareRequest(BaseModel):
    """Request to compare coverage of two inputs."""
    input_a_hash: str
    input_b_hash: str


class MinimizationRequest(BaseModel):
    """Request to start corpus minimization."""
    output_dir: Optional[str] = None
    strategy: str = Field(default="greedy")
    preserve_crashes: bool = Field(default=True)


# ============================================================================
# Session storage (in-memory for demo, should use DB in production)
# ============================================================================


_coverage_sessions: Dict[str, Dict[str, Any]] = {}
_telemetry_dirs: Dict[str, str] = {}


def _get_session_data(session_id: str) -> Dict[str, Any]:
    """Get or create session data."""
    if session_id not in _coverage_sessions:
        _coverage_sessions[session_id] = {
            "bitmap": None,
            "telemetry_dir": _telemetry_dirs.get(session_id),
            "module_data": [],
        }
    return _coverage_sessions[session_id]


def register_telemetry_dir(session_id: str, telemetry_dir: str):
    """Register telemetry directory for a session."""
    _telemetry_dirs[session_id] = telemetry_dir
    if session_id in _coverage_sessions:
        _coverage_sessions[session_id]["telemetry_dir"] = telemetry_dir


# ============================================================================
# Heatmap Endpoints
# ============================================================================


@router.get("/sessions/{session_id}/heatmap")
async def get_coverage_heatmap(
    session_id: str,
    width: int = Query(default=256, ge=32, le=1024),
    height: int = Query(default=256, ge=32, le=1024),
    color_scheme: str = Query(default="viridis"),
    log_scale: bool = Query(default=True),
    format: str = Query(default="json"),  # json, svg
    current_user: User = Depends(get_current_active_user),
) -> Any:
    """Generate coverage heatmap visualization."""
    if not VISUALIZATION_AVAILABLE:
        raise HTTPException(status_code=503, detail="Visualization service not available")

    session_data = _get_session_data(session_id)
    bitmap = session_data.get("bitmap")
    telemetry_dir = session_data.get("telemetry_dir")

    service = CoverageVisualizationService(
        coverage_bitmap=bitmap,
        telemetry_dir=telemetry_dir,
        session_id=session_id,
    )

    config = CoverageHeatmapConfig(
        width=width,
        height=height,
        color_scheme=color_scheme,
        log_scale=log_scale,
    )

    if format == "svg":
        svg_content = service.generate_svg_heatmap(config)
        return Response(content=svg_content, media_type="image/svg+xml")

    heatmap = service.generate_bitmap_heatmap(config)
    return heatmap.to_dict()


@router.get("/sessions/{session_id}/heatmap/module/{module_name}")
async def get_module_heatmap(
    session_id: str,
    module_name: str,
    format: str = Query(default="svg"),
    current_user: User = Depends(get_current_active_user),
) -> Response:
    """Generate heatmap for specific module."""
    if not VISUALIZATION_AVAILABLE:
        raise HTTPException(status_code=503, detail="Visualization service not available")

    # For now, return a placeholder - module-specific heatmaps require
    # per-module coverage data which needs integration with QEMU provider
    placeholder_svg = f'''<svg xmlns="http://www.w3.org/2000/svg" width="256" height="256">
  <rect width="100%" height="100%" fill="#1a1a1a"/>
  <text x="50%" y="50%" fill="#666" text-anchor="middle" font-family="monospace" font-size="12">
    Module: {module_name}
    (Module-specific coverage requires QEMU tracing)
  </text>
</svg>'''

    return Response(content=placeholder_svg, media_type="image/svg+xml")


# ============================================================================
# Timeline Endpoints
# ============================================================================


@router.get("/sessions/{session_id}/timeline")
async def get_coverage_timeline(
    session_id: str,
    max_points: int = Query(default=500, ge=10, le=5000),
    start_time: Optional[float] = None,
    end_time: Optional[float] = None,
    current_user: User = Depends(get_current_active_user),
) -> Dict[str, Any]:
    """Get coverage timeline with trend analysis."""
    if not VISUALIZATION_AVAILABLE:
        raise HTTPException(status_code=503, detail="Visualization service not available")

    session_data = _get_session_data(session_id)
    telemetry_dir = session_data.get("telemetry_dir")

    if not telemetry_dir or not os.path.isdir(telemetry_dir):
        raise HTTPException(status_code=404, detail="Telemetry data not found for session")

    service = CoverageVisualizationService(
        telemetry_dir=telemetry_dir,
        session_id=session_id,
    )

    trends = service.build_coverage_timeline(max_points=max_points)

    # Filter by time range if specified
    timeline = trends.timeline
    if start_time is not None:
        timeline = [p for p in timeline if p.elapsed_sec >= start_time]
    if end_time is not None:
        timeline = [p for p in timeline if p.elapsed_sec <= end_time]

    return {
        "timeline": [p.to_dict() for p in timeline],
        "growth_rate": trends.growth_rate,
        "average_growth_rate": trends.average_growth_rate,
        "plateau_detected": trends.plateau_detected,
        "plateau_start_time": trends.plateau_start_time,
        "predicted_saturation": trends.predicted_saturation,
        "total_duration_sec": trends.total_duration_sec,
        "peak_edges": trends.peak_edges,
    }


@router.get("/sessions/{session_id}/growth-rate")
async def get_coverage_growth_rate(
    session_id: str,
    window_seconds: int = Query(default=300, ge=10, le=3600),
    current_user: User = Depends(get_current_active_user),
) -> Dict[str, Any]:
    """Get current coverage growth rate."""
    if not VISUALIZATION_AVAILABLE:
        raise HTTPException(status_code=503, detail="Visualization service not available")

    session_data = _get_session_data(session_id)
    telemetry_dir = session_data.get("telemetry_dir")

    if not telemetry_dir:
        raise HTTPException(status_code=404, detail="Telemetry data not found")

    service = CoverageVisualizationService(
        telemetry_dir=telemetry_dir,
        session_id=session_id,
    )

    trends = service.build_coverage_timeline(max_points=1000)

    # Calculate windowed growth rate
    recent_points = [
        p for p in trends.timeline
        if p.elapsed_sec >= trends.total_duration_sec - window_seconds
    ]

    windowed_rate = 0.0
    if len(recent_points) >= 2:
        edge_diff = recent_points[-1].edges_total - recent_points[0].edges_total
        time_diff = recent_points[-1].elapsed_sec - recent_points[0].elapsed_sec
        if time_diff > 0:
            windowed_rate = edge_diff / time_diff

    return {
        "growth_rate": trends.growth_rate,
        "windowed_growth_rate": windowed_rate,
        "window_seconds": window_seconds,
        "plateau_detected": trends.plateau_detected,
    }


# ============================================================================
# Module Breakdown Endpoints
# ============================================================================


@router.get("/sessions/{session_id}/modules")
async def get_module_coverage(
    session_id: str,
    current_user: User = Depends(get_current_active_user),
) -> Dict[str, Any]:
    """Get coverage breakdown by module."""
    if not VISUALIZATION_AVAILABLE:
        raise HTTPException(status_code=503, detail="Visualization service not available")

    session_data = _get_session_data(session_id)
    module_data = session_data.get("module_data", [])

    service = CoverageVisualizationService(session_id=session_id)
    breakdown = service.get_module_breakdown(module_data=module_data)

    return breakdown.to_dict()


@router.get("/sessions/{session_id}/functions")
async def get_function_coverage(
    session_id: str,
    min_coverage_pct: float = Query(default=0, ge=0, le=100),
    include_uncovered: bool = Query(default=True),
    limit: int = Query(default=200, ge=1, le=1000),
    current_user: User = Depends(get_current_active_user),
) -> Dict[str, Any]:
    """Get per-function coverage if symbols available."""
    if not VISUALIZATION_AVAILABLE:
        raise HTTPException(status_code=503, detail="Visualization service not available")

    # This requires binary path and runtime coverage data
    # Return placeholder for now
    return {
        "functions": [],
        "total_functions": 0,
        "covered_functions": 0,
        "note": "Function-level coverage requires binary path and runtime tracing",
    }


# ============================================================================
# Gap Analysis Endpoints
# ============================================================================


@router.get("/sessions/{session_id}/gaps")
async def get_coverage_gaps(
    session_id: str,
    max_gaps: int = Query(default=50, ge=1, le=200),
    current_user: User = Depends(get_current_active_user),
) -> Dict[str, Any]:
    """Analyze uncovered code regions."""
    if not VISUALIZATION_AVAILABLE:
        raise HTTPException(status_code=503, detail="Visualization service not available")

    session_data = _get_session_data(session_id)
    bitmap = session_data.get("bitmap")

    service = CoverageVisualizationService(
        coverage_bitmap=bitmap,
        session_id=session_id,
    )

    gaps = service.analyze_coverage_gaps()

    result = gaps.to_dict()
    result["uncovered_regions"] = result["uncovered_regions"][:max_gaps]

    return result


@router.get("/sessions/{session_id}/recommendations")
async def get_coverage_recommendations(
    session_id: str,
    current_user: User = Depends(get_current_active_user),
) -> Dict[str, Any]:
    """Get AI recommendations for improving coverage."""
    if not VISUALIZATION_AVAILABLE:
        raise HTTPException(status_code=503, detail="Visualization service not available")

    session_data = _get_session_data(session_id)
    bitmap = session_data.get("bitmap")
    telemetry_dir = session_data.get("telemetry_dir")

    service = CoverageVisualizationService(
        coverage_bitmap=bitmap,
        telemetry_dir=telemetry_dir,
        session_id=session_id,
    )

    gaps = service.analyze_coverage_gaps()
    trends = service.build_coverage_timeline()

    recommendations = list(gaps.recommendations)

    # Add trend-based recommendations
    if trends.plateau_detected:
        recommendations.append(
            f"Coverage plateau detected at {trends.plateau_start_time:.0f}s. "
            "Consider triggering concolic execution to find new paths."
        )

    if trends.growth_rate < 0.001 and trends.total_duration_sec > 300:
        recommendations.append(
            "Very low growth rate. Consider enabling LAF-Intel for comparison splitting."
        )

    return {
        "recommendations": recommendations,
        "priority_targets": gaps.priority_targets,
        "coverage_percentage": gaps.coverage_percentage,
        "plateau_detected": trends.plateau_detected,
    }


# ============================================================================
# Dashboard Data
# ============================================================================


@router.get("/sessions/{session_id}/dashboard")
async def get_coverage_dashboard(
    session_id: str,
    current_user: User = Depends(get_current_active_user),
) -> Dict[str, Any]:
    """Get all coverage dashboard data in one call."""
    if not VISUALIZATION_AVAILABLE:
        raise HTTPException(status_code=503, detail="Visualization service not available")

    session_data = _get_session_data(session_id)
    bitmap = session_data.get("bitmap")
    telemetry_dir = session_data.get("telemetry_dir")

    if telemetry_dir and os.path.isdir(telemetry_dir):
        return generate_coverage_dashboard(
            session_id=session_id,
            telemetry_dir=telemetry_dir,
            coverage_bitmap=bitmap,
        )

    # Return minimal dashboard if no telemetry
    service = CoverageVisualizationService(
        coverage_bitmap=bitmap,
        session_id=session_id,
    )

    heatmap = service.generate_bitmap_heatmap(CoverageHeatmapConfig(width=128, height=128))

    return {
        "session_id": session_id,
        "summary": {
            "coverage_percentage": heatmap.coverage_percentage,
            "covered_edges": heatmap.covered_edges,
            "total_edges": heatmap.total_edges,
        },
        "heatmap": heatmap.to_dict(),
        "trends": None,
        "gaps": None,
    }


# ============================================================================
# Export Endpoints
# ============================================================================


@router.get("/sessions/{session_id}/export")
async def export_coverage_data(
    session_id: str,
    format: str = Query(default="json"),  # json, html, csv
    current_user: User = Depends(get_current_active_user),
) -> Response:
    """Export coverage data in specified format."""
    if not VISUALIZATION_AVAILABLE:
        raise HTTPException(status_code=503, detail="Visualization service not available")

    session_data = _get_session_data(session_id)
    bitmap = session_data.get("bitmap")
    telemetry_dir = session_data.get("telemetry_dir")

    service = CoverageVisualizationService(
        coverage_bitmap=bitmap,
        telemetry_dir=telemetry_dir,
        session_id=session_id,
    )

    if format == "html":
        html_content = service.export_html_report(
            title=f"Coverage Report - Session {session_id}"
        )
        return HTMLResponse(content=html_content)

    elif format == "csv":
        csv_content = service.export_csv()
        return PlainTextResponse(
            content=csv_content,
            media_type="text/csv",
            headers={"Content-Disposition": f"attachment; filename=coverage_{session_id}.csv"}
        )

    else:  # json
        json_data = service.export_json()
        return Response(
            content=str(json_data).encode(),
            media_type="application/json",
            headers={"Content-Disposition": f"attachment; filename=coverage_{session_id}.json"}
        )


# ============================================================================
# Corpus Coverage Endpoints
# ============================================================================


@router.get("/sessions/{session_id}/corpus/coverage")
async def get_corpus_coverage_summary(
    session_id: str,
    current_user: User = Depends(get_current_active_user),
) -> Dict[str, Any]:
    """Get coverage summary for entire corpus."""
    session_data = _get_session_data(session_id)
    telemetry_dir = session_data.get("telemetry_dir")

    # Get corpus stats from telemetry if available
    corpus_stats = {
        "total_inputs": 0,
        "total_edges_covered": 0,
        "average_edges_per_input": 0,
        "favored_inputs": 0,
        "redundant_inputs": 0,
    }

    if telemetry_dir and TELEMETRY_AVAILABLE:
        summary = load_summary(telemetry_dir)
        if summary:
            corpus_stats["total_inputs"] = summary.get("max_queue", {}).get("count", 0)

    return corpus_stats


@router.get("/sessions/{session_id}/corpus/{input_id}/coverage")
async def get_input_coverage(
    session_id: str,
    input_id: str,
    current_user: User = Depends(get_current_active_user),
) -> Dict[str, Any]:
    """Get coverage data for specific input."""
    # This requires per-input coverage tracking
    return {
        "input_id": input_id,
        "edge_count": 0,
        "unique_edges": 0,
        "new_edges_added": 0,
        "favored": False,
        "note": "Per-input coverage requires coverage persistence feature",
    }


@router.post("/sessions/{session_id}/corpus/compare")
async def compare_input_coverage(
    session_id: str,
    request: CorpusCompareRequest,
    current_user: User = Depends(get_current_active_user),
) -> Dict[str, Any]:
    """Compare coverage between two inputs."""
    # This requires per-input coverage tracking
    return {
        "input_a": request.input_a_hash,
        "input_b": request.input_b_hash,
        "edges_only_a": 0,
        "edges_only_b": 0,
        "edges_common": 0,
        "similarity": 0.0,
        "note": "Coverage comparison requires per-input coverage tracking",
    }


@router.get("/sessions/{session_id}/corpus/redundant")
async def find_redundant_inputs(
    session_id: str,
    current_user: User = Depends(get_current_active_user),
) -> Dict[str, Any]:
    """Find inputs with no unique coverage."""
    return {
        "redundant_inputs": [],
        "total_analyzed": 0,
        "potential_savings_bytes": 0,
        "note": "Redundancy analysis requires per-input coverage tracking",
    }


# ============================================================================
# QEMU Coverage Endpoints
# ============================================================================


@router.get("/qemu/capabilities")
async def get_qemu_coverage_capabilities(
    current_user: User = Depends(get_current_active_user),
) -> Dict[str, Any]:
    """Get QEMU coverage extraction capabilities."""
    if not QEMU_AVAILABLE:
        return {
            "available": False,
            "error": "QEMU coverage service not available",
        }

    return check_qemu_coverage_availability()


@router.post("/qemu/trace")
async def run_qemu_coverage_trace(
    request: QemuTraceRequest,
    input_file: UploadFile = File(...),
    current_user: User = Depends(get_current_active_user),
) -> Dict[str, Any]:
    """Run single execution with QEMU coverage tracing."""
    if not QEMU_AVAILABLE:
        raise HTTPException(status_code=503, detail="QEMU coverage not available")

    # Validate target path
    if not os.path.isfile(request.target_path):
        raise HTTPException(status_code=400, detail="Target binary not found")

    # Read input data
    input_data = await input_file.read()

    # Parse architecture
    architecture = None
    if request.architecture:
        try:
            architecture = QemuArchitecture(request.architecture)
        except ValueError:
            raise HTTPException(status_code=400, detail=f"Invalid architecture: {request.architecture}")

    # Create provider
    provider = await create_qemu_coverage_provider(
        target_path=request.target_path,
        architecture=architecture,
        compcov_level=request.compcov_level,
    )

    if not provider:
        raise HTTPException(status_code=503, detail="Could not create QEMU coverage provider")

    try:
        result = await provider.run_traced_execution(
            input_data=input_data,
            timeout_ms=request.timeout_ms,
        )
        return result.to_dict()
    finally:
        provider.close()


# ============================================================================
# Session Management Endpoints
# ============================================================================


@router.post("/sessions/{session_id}/bitmap")
async def upload_coverage_bitmap(
    session_id: str,
    bitmap_file: UploadFile = File(...),
    current_user: User = Depends(get_current_active_user),
) -> Dict[str, Any]:
    """Upload a coverage bitmap for a session."""
    bitmap_data = await bitmap_file.read()

    session_data = _get_session_data(session_id)
    session_data["bitmap"] = bitmap_data

    covered = sum(1 for b in bitmap_data if b > 0)

    return {
        "session_id": session_id,
        "bitmap_size": len(bitmap_data),
        "covered_edges": covered,
        "coverage_percentage": (covered / len(bitmap_data) * 100) if bitmap_data else 0,
    }


@router.post("/sessions/{session_id}/telemetry-dir")
async def set_telemetry_directory(
    session_id: str,
    telemetry_dir: str = Query(...),
    current_user: User = Depends(get_current_active_user),
) -> Dict[str, Any]:
    """Set the telemetry directory for a session."""
    if not os.path.isdir(telemetry_dir):
        raise HTTPException(status_code=400, detail="Telemetry directory not found")

    register_telemetry_dir(session_id, telemetry_dir)

    return {
        "session_id": session_id,
        "telemetry_dir": telemetry_dir,
        "status": "registered",
    }


@router.delete("/sessions/{session_id}")
async def delete_coverage_session(
    session_id: str,
    current_user: User = Depends(get_current_active_user),
) -> Dict[str, Any]:
    """Delete coverage session data."""
    if session_id in _coverage_sessions:
        del _coverage_sessions[session_id]
    if session_id in _telemetry_dirs:
        del _telemetry_dirs[session_id]

    return {
        "session_id": session_id,
        "status": "deleted",
    }
