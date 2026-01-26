"""
Coverage Visualization Service - Generate coverage visualizations for fuzzing sessions.

This service provides:
- Bitmap heatmap generation (SVG/JSON)
- Coverage timeline and trend analysis
- Module/function coverage breakdown
- Coverage gap analysis
- Export to various formats (JSON, HTML, CSV)
"""

import colorsys
import hashlib
import json
import math
import os
import statistics
import struct
import subprocess
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple

from .afl_telemetry_service import (
    load_telemetry_samples,
    load_summary,
    build_stats_history,
)


# ============================================================================
# Color Schemes for Heatmaps
# ============================================================================


def _viridis_color(value: float) -> Tuple[int, int, int]:
    """Viridis colormap (0.0 to 1.0) -> RGB."""
    # Simplified viridis approximation
    colors = [
        (68, 1, 84),      # 0.0 - dark purple
        (72, 40, 120),    # 0.1
        (62, 73, 137),    # 0.2
        (49, 104, 142),   # 0.3
        (38, 130, 142),   # 0.4
        (31, 158, 137),   # 0.5
        (53, 183, 121),   # 0.6
        (109, 205, 89),   # 0.7
        (180, 222, 44),   # 0.8
        (253, 231, 37),   # 1.0 - yellow
    ]

    idx = min(int(value * (len(colors) - 1)), len(colors) - 2)
    frac = (value * (len(colors) - 1)) - idx

    r = int(colors[idx][0] + frac * (colors[idx + 1][0] - colors[idx][0]))
    g = int(colors[idx][1] + frac * (colors[idx + 1][1] - colors[idx][1]))
    b = int(colors[idx][2] + frac * (colors[idx + 1][2] - colors[idx][2]))

    return (r, g, b)


def _plasma_color(value: float) -> Tuple[int, int, int]:
    """Plasma colormap (0.0 to 1.0) -> RGB."""
    colors = [
        (13, 8, 135),     # 0.0 - dark blue
        (75, 3, 161),     # 0.1
        (125, 3, 168),    # 0.2
        (168, 34, 150),   # 0.3
        (203, 70, 121),   # 0.4
        (229, 107, 93),   # 0.5
        (248, 148, 65),   # 0.6
        (253, 191, 47),   # 0.7
        (240, 230, 33),   # 0.8
        (240, 249, 33),   # 1.0 - yellow
    ]

    idx = min(int(value * (len(colors) - 1)), len(colors) - 2)
    frac = (value * (len(colors) - 1)) - idx

    r = int(colors[idx][0] + frac * (colors[idx + 1][0] - colors[idx][0]))
    g = int(colors[idx][1] + frac * (colors[idx + 1][1] - colors[idx][1]))
    b = int(colors[idx][2] + frac * (colors[idx + 1][2] - colors[idx][2]))

    return (r, g, b)


def _inferno_color(value: float) -> Tuple[int, int, int]:
    """Inferno colormap (0.0 to 1.0) -> RGB."""
    colors = [
        (0, 0, 4),        # 0.0 - black
        (40, 11, 84),     # 0.1
        (101, 21, 110),   # 0.2
        (159, 42, 99),    # 0.3
        (212, 72, 66),    # 0.4
        (245, 125, 21),   # 0.5
        (250, 175, 12),   # 0.6
        (245, 219, 76),   # 0.7
        (252, 255, 164),  # 1.0 - white/yellow
    ]

    idx = min(int(value * (len(colors) - 1)), len(colors) - 2)
    frac = (value * (len(colors) - 1)) - idx

    r = int(colors[idx][0] + frac * (colors[idx + 1][0] - colors[idx][0]))
    g = int(colors[idx][1] + frac * (colors[idx + 1][1] - colors[idx][1]))
    b = int(colors[idx][2] + frac * (colors[idx + 1][2] - colors[idx][2]))

    return (r, g, b)


COLOR_SCHEMES = {
    "viridis": _viridis_color,
    "plasma": _plasma_color,
    "inferno": _inferno_color,
}


# ============================================================================
# Dataclasses
# ============================================================================


@dataclass
class CoverageHeatmapConfig:
    """Configuration for heatmap generation."""
    width: int = 256
    height: int = 256
    color_scheme: str = "viridis"  # viridis, plasma, inferno
    log_scale: bool = True
    include_annotations: bool = True
    show_grid: bool = False
    cell_size: int = 1  # Pixel size per cell

    def to_dict(self) -> Dict[str, Any]:
        return {
            "width": self.width,
            "height": self.height,
            "color_scheme": self.color_scheme,
            "log_scale": self.log_scale,
            "include_annotations": self.include_annotations,
        }


@dataclass
class CoverageHeatmapData:
    """Data for rendering a coverage heatmap."""
    width: int
    height: int
    data: List[List[int]]  # 2D array of hit counts
    min_value: int
    max_value: int
    total_edges: int
    covered_edges: int
    coverage_percentage: float
    svg_content: Optional[str] = None
    color_scheme: str = "viridis"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "width": self.width,
            "height": self.height,
            "data": self.data,
            "min_value": self.min_value,
            "max_value": self.max_value,
            "total_edges": self.total_edges,
            "covered_edges": self.covered_edges,
            "coverage_percentage": round(self.coverage_percentage, 2),
        }


@dataclass
class CoverageTimelinePoint:
    """Single point in coverage timeline."""
    timestamp: str
    elapsed_sec: float
    edges_total: int
    edges_new: int
    blocks_hit: int
    exec_count: int
    corpus_size: int
    crashes: int = 0
    hangs: int = 0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "timestamp": self.timestamp,
            "elapsed_sec": round(self.elapsed_sec, 2),
            "edges_total": self.edges_total,
            "edges_new": self.edges_new,
            "blocks_hit": self.blocks_hit,
            "exec_count": self.exec_count,
            "corpus_size": self.corpus_size,
            "crashes": self.crashes,
            "hangs": self.hangs,
        }


@dataclass
class CoverageTrendData:
    """Coverage trend analysis data."""
    timeline: List[CoverageTimelinePoint]
    growth_rate: float  # edges per second (recent)
    average_growth_rate: float  # edges per second (overall)
    plateau_detected: bool
    plateau_start_time: Optional[float]
    predicted_saturation: Optional[float]  # estimated total edges
    total_duration_sec: float
    peak_edges: int
    final_coverage_pct: float

    def to_dict(self) -> Dict[str, Any]:
        return {
            "timeline": [p.to_dict() for p in self.timeline],
            "growth_rate": round(self.growth_rate, 4),
            "average_growth_rate": round(self.average_growth_rate, 4),
            "plateau_detected": self.plateau_detected,
            "plateau_start_time": round(self.plateau_start_time, 2) if self.plateau_start_time else None,
            "predicted_saturation": int(self.predicted_saturation) if self.predicted_saturation else None,
            "total_duration_sec": round(self.total_duration_sec, 2),
            "peak_edges": self.peak_edges,
            "final_coverage_pct": round(self.final_coverage_pct, 2),
        }


@dataclass
class ModuleCoverageBreakdown:
    """Coverage breakdown by module."""
    modules: List[Dict[str, Any]]
    total_modules: int
    fully_covered: int
    partially_covered: int
    uncovered: int
    main_binary_coverage_pct: float

    def to_dict(self) -> Dict[str, Any]:
        return {
            "modules": self.modules,
            "total_modules": self.total_modules,
            "fully_covered": self.fully_covered,
            "partially_covered": self.partially_covered,
            "uncovered": self.uncovered,
            "main_binary_coverage_pct": round(self.main_binary_coverage_pct, 2),
        }


@dataclass
class CoverageGap:
    """An uncovered region in the code."""
    module: str
    function: Optional[str]
    start_address: Optional[int]
    end_address: Optional[int]
    size_blocks: int
    priority: float  # 0-1
    reason: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "module": self.module,
            "function": self.function,
            "start_address": hex(self.start_address) if self.start_address else None,
            "end_address": hex(self.end_address) if self.end_address else None,
            "size_blocks": self.size_blocks,
            "priority": round(self.priority, 2),
            "reason": self.reason,
        }


@dataclass
class CoverageGapAnalysis:
    """Analysis of unreached code regions."""
    total_blocks: int
    covered_blocks: int
    coverage_percentage: float
    uncovered_regions: List[CoverageGap]
    priority_targets: List[str]
    recommendations: List[str]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "total_blocks": self.total_blocks,
            "covered_blocks": self.covered_blocks,
            "coverage_percentage": round(self.coverage_percentage, 2),
            "uncovered_regions": [r.to_dict() for r in self.uncovered_regions[:50]],
            "priority_targets": self.priority_targets[:20],
            "recommendations": self.recommendations,
        }


# ============================================================================
# Coverage Visualization Service
# ============================================================================


class CoverageVisualizationService:
    """
    Generates coverage visualizations for fuzzing sessions.

    Usage:
        service = CoverageVisualizationService(bitmap, telemetry_dir)
        heatmap = service.generate_bitmap_heatmap(config)
        trends = service.build_coverage_timeline(max_points=500)
    """

    def __init__(
        self,
        coverage_bitmap: Optional[bytes] = None,
        telemetry_dir: Optional[str] = None,
        session_id: Optional[str] = None,
    ):
        self.coverage_bitmap = coverage_bitmap
        self.telemetry_dir = telemetry_dir
        self.session_id = session_id
        self._bitmap_size = len(coverage_bitmap) if coverage_bitmap else 65536

    # =========================================================================
    # Heatmap Generation
    # =========================================================================

    def generate_bitmap_heatmap(
        self,
        config: Optional[CoverageHeatmapConfig] = None,
    ) -> CoverageHeatmapData:
        """
        Generate 2D heatmap from coverage bitmap.

        The bitmap is reshaped into a 2D grid where each cell represents
        a range of edge IDs, with color intensity showing hit counts.
        """
        config = config or CoverageHeatmapConfig()

        if not self.coverage_bitmap:
            return CoverageHeatmapData(
                width=config.width,
                height=config.height,
                data=[],
                min_value=0,
                max_value=0,
                total_edges=0,
                covered_edges=0,
                coverage_percentage=0.0,
            )

        # Calculate grid dimensions
        total_cells = config.width * config.height
        bitmap_len = len(self.coverage_bitmap)
        cells_per_bucket = max(1, bitmap_len // total_cells)

        # Build 2D data array
        data: List[List[int]] = []
        covered_edges = 0
        max_value = 0
        min_value = float('inf')

        for y in range(config.height):
            row = []
            for x in range(config.width):
                cell_idx = y * config.width + x
                start = cell_idx * cells_per_bucket
                end = min(start + cells_per_bucket, bitmap_len)

                # Sum hit counts for this cell
                cell_value = 0
                for i in range(start, end):
                    hit = self.coverage_bitmap[i]
                    if hit > 0:
                        cell_value += hit
                        covered_edges += 1

                row.append(cell_value)
                if cell_value > max_value:
                    max_value = cell_value
                if cell_value > 0 and cell_value < min_value:
                    min_value = cell_value

            data.append(row)

        if min_value == float('inf'):
            min_value = 0

        coverage_pct = (covered_edges / bitmap_len * 100) if bitmap_len > 0 else 0

        return CoverageHeatmapData(
            width=config.width,
            height=config.height,
            data=data,
            min_value=int(min_value),
            max_value=int(max_value),
            total_edges=bitmap_len,
            covered_edges=covered_edges,
            coverage_percentage=coverage_pct,
            color_scheme=config.color_scheme,
        )

    def generate_svg_heatmap(
        self,
        config: Optional[CoverageHeatmapConfig] = None,
    ) -> str:
        """Generate SVG heatmap visualization."""
        config = config or CoverageHeatmapConfig()
        heatmap_data = self.generate_bitmap_heatmap(config)

        if not heatmap_data.data:
            return self._empty_svg(config.width, config.height)

        # Get color function
        color_func = COLOR_SCHEMES.get(config.color_scheme, _viridis_color)

        # Calculate cell size
        cell_width = max(1, config.width // len(heatmap_data.data[0]) if heatmap_data.data else 1)
        cell_height = max(1, config.height // len(heatmap_data.data))

        svg_width = len(heatmap_data.data[0]) * cell_width
        svg_height = len(heatmap_data.data) * cell_height

        # Build SVG
        svg_parts = [
            f'<svg xmlns="http://www.w3.org/2000/svg" width="{svg_width}" height="{svg_height}" viewBox="0 0 {svg_width} {svg_height}">',
            '<style>rect{stroke:none}</style>',
        ]

        max_val = heatmap_data.max_value if heatmap_data.max_value > 0 else 1

        for y, row in enumerate(heatmap_data.data):
            for x, value in enumerate(row):
                if value > 0:
                    # Normalize value (optionally log scale)
                    if config.log_scale and value > 0:
                        norm_value = math.log1p(value) / math.log1p(max_val)
                    else:
                        norm_value = value / max_val

                    r, g, b = color_func(norm_value)
                    svg_parts.append(
                        f'<rect x="{x * cell_width}" y="{y * cell_height}" '
                        f'width="{cell_width}" height="{cell_height}" '
                        f'fill="rgb({r},{g},{b})"/>'
                    )
                else:
                    # Uncovered - dark background
                    svg_parts.append(
                        f'<rect x="{x * cell_width}" y="{y * cell_height}" '
                        f'width="{cell_width}" height="{cell_height}" '
                        f'fill="rgb(20,20,20)"/>'
                    )

        # Add annotations if requested
        if config.include_annotations:
            svg_parts.append(
                f'<text x="5" y="15" fill="white" font-size="10" font-family="monospace">'
                f'Coverage: {heatmap_data.coverage_percentage:.1f}% '
                f'({heatmap_data.covered_edges}/{heatmap_data.total_edges} edges)</text>'
            )

        svg_parts.append('</svg>')
        return '\n'.join(svg_parts)

    def _empty_svg(self, width: int, height: int) -> str:
        """Generate empty SVG placeholder."""
        return f'''<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}">
  <rect width="100%" height="100%" fill="#1a1a1a"/>
  <text x="50%" y="50%" fill="#666" text-anchor="middle" font-family="monospace" font-size="14">
    No coverage data
  </text>
</svg>'''

    # =========================================================================
    # Timeline/Trends
    # =========================================================================

    def build_coverage_timeline(
        self,
        max_points: int = 500,
    ) -> CoverageTrendData:
        """Build coverage timeline from telemetry data."""
        if not self.telemetry_dir:
            return CoverageTrendData(
                timeline=[],
                growth_rate=0.0,
                average_growth_rate=0.0,
                plateau_detected=False,
                plateau_start_time=None,
                predicted_saturation=None,
                total_duration_sec=0.0,
                peak_edges=0,
                final_coverage_pct=0.0,
            )

        samples = load_telemetry_samples(self.telemetry_dir, max_samples=max_points)

        if not samples:
            return CoverageTrendData(
                timeline=[],
                growth_rate=0.0,
                average_growth_rate=0.0,
                plateau_detected=False,
                plateau_start_time=None,
                predicted_saturation=None,
                total_duration_sec=0.0,
                peak_edges=0,
                final_coverage_pct=0.0,
            )

        # Build timeline
        timeline: List[CoverageTimelinePoint] = []
        prev_edges = 0

        for sample in samples:
            stats = sample.get("stats", {})
            queue = sample.get("queue", {})
            crashes = sample.get("crashes", {})
            hangs = sample.get("hangs", {})

            edges = stats.get("edges_found", stats.get("map_size", 0))
            new_edges = edges - prev_edges

            point = CoverageTimelinePoint(
                timestamp=sample.get("ts", ""),
                elapsed_sec=sample.get("elapsed_sec", 0.0),
                edges_total=edges,
                edges_new=max(0, new_edges),
                blocks_hit=stats.get("total_paths", 0),
                exec_count=stats.get("execs_done", 0),
                corpus_size=queue.get("count", 0),
                crashes=crashes.get("count", 0),
                hangs=hangs.get("count", 0),
            )
            timeline.append(point)
            prev_edges = edges

        # Calculate metrics
        total_duration = timeline[-1].elapsed_sec if timeline else 0.0
        peak_edges = max(p.edges_total for p in timeline) if timeline else 0

        # Calculate growth rates
        growth_rate = self.calculate_growth_rate(timeline, window_size=20)
        avg_growth_rate = peak_edges / total_duration if total_duration > 0 else 0.0

        # Detect plateau
        plateau_detected, plateau_time = self.detect_plateau(timeline)

        # Predict saturation
        predicted_saturation = self.predict_saturation(timeline)

        # Final coverage percentage (using bitmap density if available)
        final_coverage_pct = 0.0
        if timeline:
            last_sample = samples[-1] if samples else {}
            final_coverage_pct = last_sample.get("stats", {}).get("bitmap_cvg", 0.0)
            if isinstance(final_coverage_pct, str):
                final_coverage_pct = float(final_coverage_pct.rstrip('%'))

        return CoverageTrendData(
            timeline=timeline,
            growth_rate=growth_rate,
            average_growth_rate=avg_growth_rate,
            plateau_detected=plateau_detected,
            plateau_start_time=plateau_time,
            predicted_saturation=predicted_saturation,
            total_duration_sec=total_duration,
            peak_edges=peak_edges,
            final_coverage_pct=final_coverage_pct,
        )

    def calculate_growth_rate(
        self,
        timeline: List[CoverageTimelinePoint],
        window_size: int = 10,
    ) -> float:
        """Calculate moving average coverage growth rate (edges/sec)."""
        if len(timeline) < 2:
            return 0.0

        # Use last window_size points
        recent = timeline[-window_size:] if len(timeline) > window_size else timeline

        if len(recent) < 2:
            return 0.0

        edge_diff = recent[-1].edges_total - recent[0].edges_total
        time_diff = recent[-1].elapsed_sec - recent[0].elapsed_sec

        if time_diff <= 0:
            return 0.0

        return edge_diff / time_diff

    def detect_plateau(
        self,
        timeline: List[CoverageTimelinePoint],
        threshold_pct: float = 0.01,
        window_samples: int = 20,
    ) -> Tuple[bool, Optional[float]]:
        """Detect if coverage has plateaued (less than threshold growth)."""
        if len(timeline) < window_samples * 2:
            return False, None

        # Check if growth in last window is less than threshold
        recent = timeline[-window_samples:]
        start_edges = recent[0].edges_total
        end_edges = recent[-1].edges_total

        if start_edges == 0:
            return False, None

        growth_pct = (end_edges - start_edges) / start_edges

        if growth_pct < threshold_pct:
            # Find when plateau started
            for i in range(len(timeline) - window_samples, 0, -1):
                window = timeline[i:i + window_samples]
                w_start = window[0].edges_total
                w_end = window[-1].edges_total
                if w_start > 0:
                    w_growth = (w_end - w_start) / w_start
                    if w_growth >= threshold_pct:
                        return True, timeline[i + window_samples].elapsed_sec
            return True, timeline[window_samples].elapsed_sec

        return False, None

    def predict_saturation(
        self,
        timeline: List[CoverageTimelinePoint],
    ) -> Optional[float]:
        """
        Predict total reachable edges using curve fitting.

        Uses a simple logarithmic model to estimate saturation point.
        """
        if len(timeline) < 20:
            return None

        # Extract data points
        times = [p.elapsed_sec for p in timeline if p.elapsed_sec > 0]
        edges = [p.edges_total for p in timeline if p.elapsed_sec > 0]

        if len(times) < 10 or max(edges) == 0:
            return None

        # Simple extrapolation: if growth is slowing, estimate final value
        # Using last third of data to fit log curve

        last_third = len(edges) // 3
        recent_edges = edges[-last_third:]
        recent_times = times[-last_third:]

        if not recent_times or recent_times[-1] == recent_times[0]:
            return None

        # Calculate growth rate trend
        growth_rates = []
        for i in range(1, len(recent_edges)):
            time_delta = recent_times[i] - recent_times[i-1]
            if time_delta > 0:
                rate = (recent_edges[i] - recent_edges[i-1]) / time_delta
                growth_rates.append(rate)

        if not growth_rates:
            return None

        avg_rate = statistics.mean(growth_rates)
        if avg_rate <= 0:
            # Growth has stopped, current is close to saturation
            return float(max(edges))

        # Estimate using diminishing returns model
        current_edges = edges[-1]
        # If growth is slowing, estimate ~50% more edges reachable
        estimated_saturation = current_edges * 1.5

        return estimated_saturation

    # =========================================================================
    # Module Breakdown
    # =========================================================================

    def get_module_breakdown(
        self,
        binary_path: Optional[str] = None,
        module_data: Optional[List[Dict[str, Any]]] = None,
    ) -> ModuleCoverageBreakdown:
        """Get coverage broken down by module/library."""
        modules = module_data or []

        if not modules and binary_path:
            # Try to extract from binary
            modules = self._extract_modules_from_binary(binary_path)

        if not modules:
            return ModuleCoverageBreakdown(
                modules=[],
                total_modules=0,
                fully_covered=0,
                partially_covered=0,
                uncovered=0,
                main_binary_coverage_pct=0.0,
            )

        fully_covered = 0
        partially_covered = 0
        uncovered = 0
        main_binary_pct = 0.0

        for mod in modules:
            coverage_pct = mod.get("coverage_pct", mod.get("coverage_percentage", 0))
            if coverage_pct >= 99:
                fully_covered += 1
            elif coverage_pct > 0:
                partially_covered += 1
            else:
                uncovered += 1

            if mod.get("is_main_binary"):
                main_binary_pct = coverage_pct

        return ModuleCoverageBreakdown(
            modules=modules,
            total_modules=len(modules),
            fully_covered=fully_covered,
            partially_covered=partially_covered,
            uncovered=uncovered,
            main_binary_coverage_pct=main_binary_pct,
        )

    def _extract_modules_from_binary(self, binary_path: str) -> List[Dict[str, Any]]:
        """Extract module information from binary using readelf."""
        modules = []

        if not os.path.isfile(binary_path):
            return modules

        try:
            # Get binary sections
            result = subprocess.run(
                ["readelf", "-S", binary_path],
                capture_output=True,
                text=True,
                timeout=10
            )

            main_binary = os.path.basename(binary_path)
            text_size = 0

            for line in result.stdout.split('\n'):
                if '.text' in line:
                    parts = line.split()
                    for i, p in enumerate(parts):
                        if '.text' in p and i + 4 < len(parts):
                            try:
                                text_size = int(parts[i + 4], 16)
                            except (ValueError, IndexError):
                                pass

            modules.append({
                "name": main_binary,
                "is_main_binary": True,
                "blocks_total": text_size // 16 if text_size else 0,  # Estimate
                "blocks_covered": 0,  # Unknown without runtime data
                "coverage_pct": 0.0,
            })

        except Exception:
            pass

        return modules

    def analyze_function_coverage(
        self,
        binary_path: str,
    ) -> List[Dict[str, Any]]:
        """Analyze per-function coverage if symbols available."""
        functions = []

        if not os.path.isfile(binary_path):
            return functions

        try:
            result = subprocess.run(
                ["nm", "-C", "--defined-only", binary_path],
                capture_output=True,
                text=True,
                timeout=10
            )

            for line in result.stdout.strip().split('\n'):
                parts = line.split()
                if len(parts) >= 3 and parts[1].upper() == 'T':
                    func_name = " ".join(parts[2:])
                    functions.append({
                        "name": func_name,
                        "address": parts[0],
                        "covered": False,  # Unknown without runtime data
                        "hit_count": 0,
                    })

        except Exception:
            pass

        return functions[:500]  # Limit to 500 functions

    # =========================================================================
    # Gap Analysis
    # =========================================================================

    def analyze_coverage_gaps(
        self,
        binary_path: Optional[str] = None,
        module_data: Optional[List[Dict[str, Any]]] = None,
    ) -> CoverageGapAnalysis:
        """Identify uncovered regions and prioritize targets."""
        gaps: List[CoverageGap] = []
        recommendations: List[str] = []
        priority_targets: List[str] = []

        total_blocks = 0
        covered_blocks = 0

        # Calculate from bitmap if available
        if self.coverage_bitmap:
            total_blocks = len(self.coverage_bitmap)
            covered_blocks = sum(1 for b in self.coverage_bitmap if b > 0)

        # Identify gaps from bitmap
        if self.coverage_bitmap and len(self.coverage_bitmap) > 0:
            # Find continuous uncovered regions
            in_gap = False
            gap_start = 0
            gap_size = 0

            for i, hit in enumerate(self.coverage_bitmap):
                if hit == 0:
                    if not in_gap:
                        in_gap = True
                        gap_start = i
                        gap_size = 1
                    else:
                        gap_size += 1
                else:
                    if in_gap and gap_size >= 10:  # Only report gaps >= 10 edges
                        gaps.append(CoverageGap(
                            module="unknown",
                            function=None,
                            start_address=gap_start,
                            end_address=gap_start + gap_size,
                            size_blocks=gap_size,
                            priority=min(1.0, gap_size / 100),
                            reason="Uncovered edge region",
                        ))
                    in_gap = False
                    gap_size = 0

            # Handle final gap
            if in_gap and gap_size >= 10:
                gaps.append(CoverageGap(
                    module="unknown",
                    function=None,
                    start_address=gap_start,
                    end_address=gap_start + gap_size,
                    size_blocks=gap_size,
                    priority=min(1.0, gap_size / 100),
                    reason="Uncovered edge region",
                ))

        # Sort gaps by priority
        gaps.sort(key=lambda g: g.priority, reverse=True)

        # Generate recommendations
        coverage_pct = (covered_blocks / total_blocks * 100) if total_blocks > 0 else 0

        if coverage_pct < 30:
            recommendations.append("Coverage is low (<30%). Consider improving seed corpus quality.")
            recommendations.append("Run taint analysis to identify input bytes affecting uncovered code.")
        elif coverage_pct < 60:
            recommendations.append("Coverage is moderate. Consider enabling concolic execution for complex branches.")
        else:
            recommendations.append("Coverage is good (>60%). Focus on targeted analysis of remaining gaps.")

        if len(gaps) > 50:
            recommendations.append(f"Found {len(gaps)} significant coverage gaps. Prioritize largest gaps first.")

        # Extract priority targets from gaps
        for gap in gaps[:20]:
            if gap.function:
                priority_targets.append(gap.function)
            else:
                priority_targets.append(f"Region at {hex(gap.start_address or 0)}")

        return CoverageGapAnalysis(
            total_blocks=total_blocks,
            covered_blocks=covered_blocks,
            coverage_percentage=coverage_pct,
            uncovered_regions=gaps[:50],
            priority_targets=priority_targets,
            recommendations=recommendations,
        )

    # =========================================================================
    # Export
    # =========================================================================

    def export_json(self) -> Dict[str, Any]:
        """Export all visualization data as JSON."""
        heatmap = self.generate_bitmap_heatmap()
        trends = self.build_coverage_timeline()
        gaps = self.analyze_coverage_gaps()

        return {
            "session_id": self.session_id,
            "heatmap": heatmap.to_dict(),
            "trends": trends.to_dict(),
            "gaps": gaps.to_dict(),
            "generated_at": datetime.utcnow().isoformat() + "Z",
        }

    def export_html_report(
        self,
        include_charts: bool = True,
        title: str = "Coverage Report",
    ) -> str:
        """Generate standalone HTML report with embedded visualizations."""
        heatmap = self.generate_bitmap_heatmap()
        svg_heatmap = self.generate_svg_heatmap()
        trends = self.build_coverage_timeline()
        gaps = self.analyze_coverage_gaps()

        # Build timeline chart data
        timeline_json = json.dumps([p.to_dict() for p in trends.timeline])

        html = f'''<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>{title}</title>
    <style>
        body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; margin: 20px; background: #1a1a1a; color: #e0e0e0; }}
        h1, h2, h3 {{ color: #fff; }}
        .card {{ background: #2a2a2a; border-radius: 8px; padding: 20px; margin: 20px 0; }}
        .stat {{ display: inline-block; margin-right: 30px; }}
        .stat-value {{ font-size: 24px; font-weight: bold; color: #4CAF50; }}
        .stat-label {{ font-size: 12px; color: #888; }}
        .heatmap {{ display: flex; justify-content: center; margin: 20px 0; }}
        table {{ width: 100%; border-collapse: collapse; }}
        th, td {{ padding: 10px; text-align: left; border-bottom: 1px solid #444; }}
        th {{ background: #333; }}
        .progress {{ background: #333; border-radius: 4px; height: 20px; }}
        .progress-bar {{ background: #4CAF50; height: 100%; border-radius: 4px; }}
        .recommendation {{ background: #333; padding: 10px; margin: 5px 0; border-radius: 4px; border-left: 3px solid #4CAF50; }}
        #chart {{ width: 100%; height: 300px; }}
    </style>
</head>
<body>
    <h1>{title}</h1>
    <p>Generated: {datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")} UTC</p>

    <div class="card">
        <h2>Coverage Summary</h2>
        <div class="stat">
            <div class="stat-value">{heatmap.coverage_percentage:.1f}%</div>
            <div class="stat-label">Coverage</div>
        </div>
        <div class="stat">
            <div class="stat-value">{heatmap.covered_edges:,}</div>
            <div class="stat-label">Covered Edges</div>
        </div>
        <div class="stat">
            <div class="stat-value">{heatmap.total_edges:,}</div>
            <div class="stat-label">Total Edges</div>
        </div>
        <div class="stat">
            <div class="stat-value">{trends.peak_edges:,}</div>
            <div class="stat-label">Peak Edges</div>
        </div>
        <div class="stat">
            <div class="stat-value">{trends.total_duration_sec:.0f}s</div>
            <div class="stat-label">Duration</div>
        </div>
    </div>

    <div class="card">
        <h2>Coverage Heatmap</h2>
        <div class="heatmap">
            {svg_heatmap}
        </div>
    </div>

    <div class="card">
        <h2>Coverage Trend</h2>
        <p>Growth Rate: {trends.growth_rate:.4f} edges/sec (recent), {trends.average_growth_rate:.4f} edges/sec (average)</p>
        <p>Plateau Detected: {"Yes at " + str(trends.plateau_start_time) + "s" if trends.plateau_detected else "No"}</p>
        {f'<p>Predicted Saturation: {trends.predicted_saturation:,.0f} edges</p>' if trends.predicted_saturation else ''}
        <canvas id="chart"></canvas>
    </div>

    <div class="card">
        <h2>Coverage Gaps</h2>
        <p>Total Blocks: {gaps.total_blocks:,} | Covered: {gaps.covered_blocks:,} ({gaps.coverage_percentage:.1f}%)</p>
        <table>
            <tr><th>Priority</th><th>Module</th><th>Size (blocks)</th><th>Reason</th></tr>
            {''.join(f"<tr><td>{g.priority:.2f}</td><td>{g.module}</td><td>{g.size_blocks}</td><td>{g.reason}</td></tr>" for g in gaps.uncovered_regions[:20])}
        </table>
    </div>

    <div class="card">
        <h2>Recommendations</h2>
        {''.join(f'<div class="recommendation">{r}</div>' for r in gaps.recommendations)}
    </div>

    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <script>
        const timelineData = {timeline_json};
        if (timelineData.length > 0) {{
            const ctx = document.getElementById('chart').getContext('2d');
            new Chart(ctx, {{
                type: 'line',
                data: {{
                    labels: timelineData.map(p => Math.round(p.elapsed_sec) + 's'),
                    datasets: [{{
                        label: 'Edges',
                        data: timelineData.map(p => p.edges_total),
                        borderColor: '#4CAF50',
                        backgroundColor: 'rgba(76, 175, 80, 0.1)',
                        fill: true,
                        tension: 0.1
                    }}]
                }},
                options: {{
                    responsive: true,
                    scales: {{
                        y: {{ beginAtZero: true, grid: {{ color: '#333' }} }},
                        x: {{ grid: {{ color: '#333' }} }}
                    }},
                    plugins: {{
                        legend: {{ labels: {{ color: '#e0e0e0' }} }}
                    }}
                }}
            }});
        }}
    </script>
</body>
</html>'''

        return html

    def export_csv(self) -> str:
        """Export coverage timeline as CSV."""
        trends = self.build_coverage_timeline()

        lines = ["timestamp,elapsed_sec,edges_total,edges_new,exec_count,corpus_size,crashes,hangs"]
        for p in trends.timeline:
            lines.append(
                f"{p.timestamp},{p.elapsed_sec},{p.edges_total},{p.edges_new},"
                f"{p.exec_count},{p.corpus_size},{p.crashes},{p.hangs}"
            )

        return '\n'.join(lines)


# ============================================================================
# Factory Functions
# ============================================================================


def create_visualization_service(
    session_id: str,
    telemetry_dir: Optional[str] = None,
    coverage_bitmap: Optional[bytes] = None,
) -> CoverageVisualizationService:
    """Create a coverage visualization service instance."""
    return CoverageVisualizationService(
        coverage_bitmap=coverage_bitmap,
        telemetry_dir=telemetry_dir,
        session_id=session_id,
    )


def generate_coverage_dashboard(
    session_id: str,
    telemetry_dir: str,
    coverage_bitmap: Optional[bytes] = None,
) -> Dict[str, Any]:
    """Generate all coverage dashboard data in one call."""
    service = CoverageVisualizationService(
        coverage_bitmap=coverage_bitmap,
        telemetry_dir=telemetry_dir,
        session_id=session_id,
    )

    heatmap_config = CoverageHeatmapConfig(width=128, height=128)
    heatmap = service.generate_bitmap_heatmap(heatmap_config)
    trends = service.build_coverage_timeline(max_points=200)
    gaps = service.analyze_coverage_gaps()

    return {
        "session_id": session_id,
        "summary": {
            "coverage_percentage": heatmap.coverage_percentage,
            "covered_edges": heatmap.covered_edges,
            "total_edges": heatmap.total_edges,
            "peak_edges": trends.peak_edges,
            "duration_sec": trends.total_duration_sec,
            "growth_rate": trends.growth_rate,
            "plateau_detected": trends.plateau_detected,
        },
        "heatmap": heatmap.to_dict(),
        "trends": {
            "growth_rate": trends.growth_rate,
            "average_growth_rate": trends.average_growth_rate,
            "plateau_detected": trends.plateau_detected,
            "plateau_start_time": trends.plateau_start_time,
            "predicted_saturation": trends.predicted_saturation,
            "timeline_points": len(trends.timeline),
        },
        "gaps": {
            "total_blocks": gaps.total_blocks,
            "covered_blocks": gaps.covered_blocks,
            "coverage_percentage": gaps.coverage_percentage,
            "gap_count": len(gaps.uncovered_regions),
            "recommendations": gaps.recommendations,
        },
    }
