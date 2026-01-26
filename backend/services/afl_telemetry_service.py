import json
import os
from collections import deque
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Deque, Dict, List, Optional


def _iso_utc_now() -> str:
    return datetime.utcnow().isoformat() + "Z"


@dataclass
class AflDirStats:
    count: int = 0
    total_bytes: int = 0
    newest_mtime: Optional[float] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "count": self.count,
            "bytes": self.total_bytes,
            "newest_mtime": self.newest_mtime,
        }


@dataclass
class ConcolicStats:
    """Statistics from concolic execution cycles."""
    runs: int = 0
    inputs_generated: int = 0
    coverage_contributions: int = 0
    constraints_collected: int = 0
    constraints_solved: int = 0
    solver_time_total_ms: float = 0.0
    last_run: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "runs": self.runs,
            "inputs_generated": self.inputs_generated,
            "coverage_contributions": self.coverage_contributions,
            "constraints_collected": self.constraints_collected,
            "constraints_solved": self.constraints_solved,
            "solver_time_total_ms": self.solver_time_total_ms,
            "last_run": self.last_run,
        }

    def update_from_cycle(self, cycle_result: Dict[str, Any]):
        """Update stats from a concolic cycle result."""
        self.runs += 1
        self.inputs_generated += cycle_result.get("inputs_generated", 0)
        self.coverage_contributions += cycle_result.get("coverage_contributions", 0)
        self.constraints_collected += cycle_result.get("constraints_collected", 0)
        self.constraints_solved += cycle_result.get("constraints_solved", 0)
        self.solver_time_total_ms += cycle_result.get("solver_time_ms", 0.0)
        self.last_run = _iso_utc_now()


@dataclass
class TaintStats:
    """Statistics from taint tracking cycles."""
    analyses: int = 0
    hot_bytes_identified: int = 0
    guided_mutations: int = 0
    sink_hits_total: int = 0
    unique_sinks_reached: int = 0
    last_run: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "analyses": self.analyses,
            "hot_bytes_identified": self.hot_bytes_identified,
            "guided_mutations": self.guided_mutations,
            "sink_hits_total": self.sink_hits_total,
            "unique_sinks_reached": self.unique_sinks_reached,
            "last_run": self.last_run,
        }

    def update_from_cycle(self, cycle_result: Dict[str, Any]):
        """Update stats from a taint cycle result."""
        self.analyses += 1
        self.hot_bytes_identified += cycle_result.get("hot_bytes_count", 0)
        self.guided_mutations += cycle_result.get("mutations_generated", 0)
        self.sink_hits_total += cycle_result.get("sink_hits", 0)
        self.unique_sinks_reached = max(
            self.unique_sinks_reached,
            cycle_result.get("unique_sinks", 0)
        )
        self.last_run = _iso_utc_now()


@dataclass
class HybridStats:
    """Combined hybrid fuzzing statistics."""
    mode: str = "afl_only"
    concolic_enabled: bool = False
    taint_enabled: bool = False
    laf_enabled: bool = False
    concolic: ConcolicStats = field(default_factory=ConcolicStats)
    taint: TaintStats = field(default_factory=TaintStats)
    stagnation_triggers: int = 0
    manual_triggers: int = 0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "mode": self.mode,
            "concolic_enabled": self.concolic_enabled,
            "taint_enabled": self.taint_enabled,
            "laf_enabled": self.laf_enabled,
            "concolic": self.concolic.to_dict(),
            "taint": self.taint.to_dict(),
            "stagnation_triggers": self.stagnation_triggers,
            "manual_triggers": self.manual_triggers,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "HybridStats":
        """Create HybridStats from dictionary."""
        stats = cls(
            mode=data.get("mode", "afl_only"),
            concolic_enabled=data.get("concolic_enabled", False),
            taint_enabled=data.get("taint_enabled", False),
            laf_enabled=data.get("laf_enabled", False),
            stagnation_triggers=data.get("stagnation_triggers", 0),
            manual_triggers=data.get("manual_triggers", 0),
        )
        if "concolic" in data:
            c = data["concolic"]
            stats.concolic = ConcolicStats(
                runs=c.get("runs", 0),
                inputs_generated=c.get("inputs_generated", 0),
                coverage_contributions=c.get("coverage_contributions", 0),
                constraints_collected=c.get("constraints_collected", 0),
                constraints_solved=c.get("constraints_solved", 0),
                solver_time_total_ms=c.get("solver_time_total_ms", 0.0),
                last_run=c.get("last_run"),
            )
        if "taint" in data:
            t = data["taint"]
            stats.taint = TaintStats(
                analyses=t.get("analyses", 0),
                hot_bytes_identified=t.get("hot_bytes_identified", 0),
                guided_mutations=t.get("guided_mutations", 0),
                sink_hits_total=t.get("sink_hits_total", 0),
                unique_sinks_reached=t.get("unique_sinks_reached", 0),
                last_run=t.get("last_run"),
            )
        return stats


def get_afl_dir_stats(path: str, skip_names: Optional[set] = None) -> AflDirStats:
    stats = AflDirStats()
    if not os.path.isdir(path):
        return stats

    skip = skip_names or set()
    newest = None
    total_bytes = 0
    count = 0

    try:
        with os.scandir(path) as entries:
            for entry in entries:
                if not entry.is_file():
                    continue
                if entry.name in skip:
                    continue
                try:
                    st = entry.stat()
                except FileNotFoundError:
                    continue
                count += 1
                total_bytes += st.st_size
                if newest is None or st.st_mtime > newest:
                    newest = st.st_mtime
    except FileNotFoundError:
        return stats

    stats.count = count
    stats.total_bytes = total_bytes
    stats.newest_mtime = newest
    return stats


class AflTelemetryRecorder:
    def __init__(
        self,
        telemetry_dir: str,
        session_id: str,
        metadata: Dict[str, Any],
        hybrid_config: Optional[Dict[str, Any]] = None,
    ):
        self.telemetry_dir = telemetry_dir
        self.session_id = session_id
        self.started_at = _iso_utc_now()
        self.sample_count = 0
        self.last_sample: Optional[Dict[str, Any]] = None
        self.max_stats: Dict[str, Any] = {}
        self.max_queue: Dict[str, Any] = {}
        self.max_crashes: Dict[str, Any] = {}
        self.max_hangs: Dict[str, Any] = {}

        # Hybrid fuzzing stats tracking
        self.hybrid_stats: Optional[HybridStats] = None
        self.hybrid_sample_count = 0
        if hybrid_config:
            self.hybrid_stats = HybridStats(
                mode=hybrid_config.get("mode", "afl_only"),
                concolic_enabled=hybrid_config.get("concolic_enabled", False),
                taint_enabled=hybrid_config.get("taint_enabled", False),
                laf_enabled=hybrid_config.get("laf_enabled", False),
            )

        os.makedirs(self.telemetry_dir, exist_ok=True)
        self.samples_path = os.path.join(self.telemetry_dir, "samples.jsonl")
        self.hybrid_samples_path = os.path.join(self.telemetry_dir, "hybrid_samples.jsonl")
        self.run_path = os.path.join(self.telemetry_dir, "run.json")
        self.summary_path = os.path.join(self.telemetry_dir, "summary.json")

        base_metadata = {
            "schema_version": 2,  # Bumped for hybrid support
            "session_id": self.session_id,
            "started_at": self.started_at,
            "hybrid_enabled": self.hybrid_stats is not None,
        }
        if self.hybrid_stats:
            base_metadata["hybrid_config"] = {
                "mode": self.hybrid_stats.mode,
                "concolic_enabled": self.hybrid_stats.concolic_enabled,
                "taint_enabled": self.hybrid_stats.taint_enabled,
                "laf_enabled": self.hybrid_stats.laf_enabled,
            }
        base_metadata.update(metadata or {})
        self._write_json(self.run_path, base_metadata)

    def record_sample(
        self,
        stats: Dict[str, Any],
        queue: AflDirStats,
        crashes: AflDirStats,
        hangs: AflDirStats,
        runtime_seconds: float,
        include_hybrid: bool = True,
    ):
        sample = {
            "ts": _iso_utc_now(),
            "elapsed_sec": round(runtime_seconds, 3),
            "stats": stats,
            "queue": queue.to_dict(),
            "crashes": crashes.to_dict(),
            "hangs": hangs.to_dict(),
        }
        # Include hybrid stats snapshot in regular samples if enabled
        if include_hybrid and self.hybrid_stats:
            sample["hybrid"] = self.hybrid_stats.to_dict()
        self._append_jsonl(self.samples_path, sample)
        self.sample_count += 1
        self.last_sample = sample
        self._update_max(self.max_stats, stats)
        self._update_max(self.max_queue, queue.to_dict())
        self._update_max(self.max_crashes, crashes.to_dict())
        self._update_max(self.max_hangs, hangs.to_dict())

    def record_concolic_cycle(
        self,
        cycle_result: Dict[str, Any],
        runtime_seconds: float,
        trigger: str = "automatic",
    ):
        """Record a concolic execution cycle event."""
        if not self.hybrid_stats:
            return

        self.hybrid_stats.concolic.update_from_cycle(cycle_result)
        if trigger == "stagnation":
            self.hybrid_stats.stagnation_triggers += 1
        elif trigger == "manual":
            self.hybrid_stats.manual_triggers += 1

        event = {
            "ts": _iso_utc_now(),
            "elapsed_sec": round(runtime_seconds, 3),
            "type": "concolic_cycle",
            "trigger": trigger,
            "result": {
                "inputs_analyzed": cycle_result.get("inputs_analyzed", 0),
                "inputs_generated": cycle_result.get("inputs_generated", 0),
                "coverage_contributions": cycle_result.get("coverage_contributions", 0),
                "constraints_collected": cycle_result.get("constraints_collected", 0),
                "constraints_solved": cycle_result.get("constraints_solved", 0),
                "solver_time_ms": cycle_result.get("solver_time_ms", 0.0),
                "new_paths_found": cycle_result.get("new_paths_found", False),
            },
            "cumulative": self.hybrid_stats.concolic.to_dict(),
        }
        self._append_jsonl(self.hybrid_samples_path, event)
        self.hybrid_sample_count += 1

    def record_taint_cycle(
        self,
        cycle_result: Dict[str, Any],
        runtime_seconds: float,
        trigger: str = "automatic",
    ):
        """Record a taint tracking cycle event."""
        if not self.hybrid_stats:
            return

        self.hybrid_stats.taint.update_from_cycle(cycle_result)
        if trigger == "stagnation":
            self.hybrid_stats.stagnation_triggers += 1
        elif trigger == "manual":
            self.hybrid_stats.manual_triggers += 1

        event = {
            "ts": _iso_utc_now(),
            "elapsed_sec": round(runtime_seconds, 3),
            "type": "taint_cycle",
            "trigger": trigger,
            "result": {
                "inputs_analyzed": cycle_result.get("inputs_analyzed", 0),
                "hot_bytes_count": cycle_result.get("hot_bytes_count", 0),
                "mutations_generated": cycle_result.get("mutations_generated", 0),
                "sink_hits": cycle_result.get("sink_hits", 0),
                "unique_sinks": cycle_result.get("unique_sinks", 0),
                "sinks_hit": cycle_result.get("sinks_hit", []),
            },
            "cumulative": self.hybrid_stats.taint.to_dict(),
        }
        self._append_jsonl(self.hybrid_samples_path, event)
        self.hybrid_sample_count += 1

    def record_hybrid_event(
        self,
        event_type: str,
        data: Dict[str, Any],
        runtime_seconds: float,
    ):
        """Record a generic hybrid fuzzing event."""
        event = {
            "ts": _iso_utc_now(),
            "elapsed_sec": round(runtime_seconds, 3),
            "type": event_type,
            "data": data,
        }
        if self.hybrid_stats:
            event["hybrid_stats"] = self.hybrid_stats.to_dict()
        self._append_jsonl(self.hybrid_samples_path, event)
        self.hybrid_sample_count += 1

    def finalize(
        self,
        status: str,
        runtime_seconds: float,
        final_stats: Optional[Dict[str, Any]] = None,
        error: Optional[str] = None,
    ):
        summary = {
            "schema_version": 2,  # Bumped for hybrid support
            "session_id": self.session_id,
            "started_at": self.started_at,
            "ended_at": _iso_utc_now(),
            "duration_sec": round(runtime_seconds, 3),
            "status": status,
            "error": error,
            "sample_count": self.sample_count,
            "final_stats": final_stats or (self.last_sample or {}).get("stats"),
            "max_stats": self.max_stats,
            "max_queue": self.max_queue,
            "max_crashes": self.max_crashes,
            "max_hangs": self.max_hangs,
        }
        # Include hybrid stats in summary if enabled
        if self.hybrid_stats:
            summary["hybrid_enabled"] = True
            summary["hybrid_sample_count"] = self.hybrid_sample_count
            summary["hybrid_stats"] = self.hybrid_stats.to_dict()
            summary["hybrid_summary"] = {
                "total_concolic_runs": self.hybrid_stats.concolic.runs,
                "total_concolic_inputs": self.hybrid_stats.concolic.inputs_generated,
                "total_taint_analyses": self.hybrid_stats.taint.analyses,
                "total_hot_bytes": self.hybrid_stats.taint.hot_bytes_identified,
                "stagnation_triggers": self.hybrid_stats.stagnation_triggers,
                "manual_triggers": self.hybrid_stats.manual_triggers,
            }
        else:
            summary["hybrid_enabled"] = False
        self._write_json(self.summary_path, summary)

    def _update_max(self, target: Dict[str, Any], source: Dict[str, Any]):
        for key, value in source.items():
            if not isinstance(value, (int, float)):
                continue
            existing = target.get(key)
            if existing is None or value > existing:
                target[key] = value

    @staticmethod
    def _write_json(path: str, payload: Dict[str, Any]):
        with open(path, "w", encoding="utf-8") as handle:
            json.dump(payload, handle, indent=2)

    @staticmethod
    def _append_jsonl(path: str, payload: Dict[str, Any]):
        line = json.dumps(payload, separators=(",", ":"))
        with open(path, "a", encoding="utf-8") as handle:
            handle.write(line + "\n")


def load_telemetry_samples(telemetry_dir: str, max_samples: int = 0) -> List[Dict[str, Any]]:
    samples_path = os.path.join(telemetry_dir, "samples.jsonl")
    if not os.path.isfile(samples_path):
        return []

    if max_samples and max_samples > 0:
        window: Deque[Dict[str, Any]] = deque(maxlen=max_samples)
        with open(samples_path, "r", encoding="utf-8") as handle:
            for line in handle:
                line = line.strip()
                if not line:
                    continue
                try:
                    window.append(json.loads(line))
                except json.JSONDecodeError:
                    continue
        return list(window)

    samples: List[Dict[str, Any]] = []
    with open(samples_path, "r", encoding="utf-8") as handle:
        for line in handle:
            line = line.strip()
            if not line:
                continue
            try:
                samples.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    return samples


def build_stats_history(telemetry_dir: str, max_samples: int = 0) -> List[Dict[str, Any]]:
    samples = load_telemetry_samples(telemetry_dir, max_samples=max_samples)
    history = []
    for sample in samples:
        stats = dict(sample.get("stats") or {})
        stats["timestamp"] = sample.get("ts")
        stats["elapsed_sec"] = sample.get("elapsed_sec")
        history.append(stats)
    return history


def load_run_metadata(telemetry_dir: str) -> Dict[str, Any]:
    path = os.path.join(telemetry_dir, "run.json")
    if not os.path.isfile(path):
        return {}
    try:
        with open(path, "r", encoding="utf-8") as handle:
            data = json.load(handle)
        return data if isinstance(data, dict) else {}
    except Exception:
        return {}


def load_summary(telemetry_dir: str) -> Dict[str, Any]:
    path = os.path.join(telemetry_dir, "summary.json")
    if not os.path.isfile(path):
        return {}
    try:
        with open(path, "r", encoding="utf-8") as handle:
            data = json.load(handle)
        return data if isinstance(data, dict) else {}
    except Exception:
        return {}


def list_afl_inputs(
    dir_path: str,
    limit: int = 200,
    skip_names: Optional[set] = None,
) -> List[Dict[str, Any]]:
    entries = []
    if not os.path.isdir(dir_path):
        return entries

    skip = skip_names or set()
    try:
        for entry in os.scandir(dir_path):
            if not entry.is_file():
                continue
            if entry.name in skip:
                continue
            try:
                st = entry.stat()
            except FileNotFoundError:
                continue
            entries.append({
                "id": entry.name,
                "path": entry.path,
                "size": st.st_size,
                "timestamp": st.st_mtime,
            })
            if limit and len(entries) >= limit:
                break
    except FileNotFoundError:
        return entries

    return entries


# ============================================================================
# Hybrid Fuzzing Telemetry Functions
# ============================================================================


def load_hybrid_samples(
    telemetry_dir: str,
    max_samples: int = 0,
    event_type: Optional[str] = None,
) -> List[Dict[str, Any]]:
    """Load hybrid fuzzing event samples from hybrid_samples.jsonl.

    Args:
        telemetry_dir: Path to the telemetry directory
        max_samples: Maximum number of samples to return (0 = unlimited)
        event_type: Filter by event type (concolic_cycle, taint_cycle, etc.)

    Returns:
        List of hybrid event dictionaries
    """
    samples_path = os.path.join(telemetry_dir, "hybrid_samples.jsonl")
    if not os.path.isfile(samples_path):
        return []

    samples: List[Dict[str, Any]] = []
    with open(samples_path, "r", encoding="utf-8") as handle:
        for line in handle:
            line = line.strip()
            if not line:
                continue
            try:
                sample = json.loads(line)
                if event_type and sample.get("type") != event_type:
                    continue
                samples.append(sample)
            except json.JSONDecodeError:
                continue

    if max_samples and max_samples > 0:
        return samples[-max_samples:]
    return samples


def build_hybrid_stats_history(
    telemetry_dir: str,
    max_samples: int = 0,
) -> List[Dict[str, Any]]:
    """Build hybrid stats history from regular samples that include hybrid stats.

    Returns a list of hybrid stats snapshots over time.
    """
    samples = load_telemetry_samples(telemetry_dir, max_samples=max_samples)
    history = []
    for sample in samples:
        hybrid = sample.get("hybrid")
        if hybrid:
            entry = dict(hybrid)
            entry["timestamp"] = sample.get("ts")
            entry["elapsed_sec"] = sample.get("elapsed_sec")
            history.append(entry)
    return history


def build_concolic_history(
    telemetry_dir: str,
    max_samples: int = 0,
) -> List[Dict[str, Any]]:
    """Build concolic execution history from hybrid samples."""
    samples = load_hybrid_samples(
        telemetry_dir,
        max_samples=max_samples,
        event_type="concolic_cycle"
    )
    history = []
    for sample in samples:
        result = sample.get("result", {})
        cumulative = sample.get("cumulative", {})
        history.append({
            "timestamp": sample.get("ts"),
            "elapsed_sec": sample.get("elapsed_sec"),
            "trigger": sample.get("trigger"),
            "inputs_generated": result.get("inputs_generated", 0),
            "coverage_contributions": result.get("coverage_contributions", 0),
            "constraints_collected": result.get("constraints_collected", 0),
            "constraints_solved": result.get("constraints_solved", 0),
            "solver_time_ms": result.get("solver_time_ms", 0.0),
            "cumulative_runs": cumulative.get("runs", 0),
            "cumulative_inputs": cumulative.get("inputs_generated", 0),
        })
    return history


def build_taint_history(
    telemetry_dir: str,
    max_samples: int = 0,
) -> List[Dict[str, Any]]:
    """Build taint tracking history from hybrid samples."""
    samples = load_hybrid_samples(
        telemetry_dir,
        max_samples=max_samples,
        event_type="taint_cycle"
    )
    history = []
    for sample in samples:
        result = sample.get("result", {})
        cumulative = sample.get("cumulative", {})
        history.append({
            "timestamp": sample.get("ts"),
            "elapsed_sec": sample.get("elapsed_sec"),
            "trigger": sample.get("trigger"),
            "hot_bytes_count": result.get("hot_bytes_count", 0),
            "mutations_generated": result.get("mutations_generated", 0),
            "sink_hits": result.get("sink_hits", 0),
            "unique_sinks": result.get("unique_sinks", 0),
            "sinks_hit": result.get("sinks_hit", []),
            "cumulative_analyses": cumulative.get("analyses", 0),
            "cumulative_hot_bytes": cumulative.get("hot_bytes_identified", 0),
        })
    return history


def get_hybrid_summary(telemetry_dir: str) -> Dict[str, Any]:
    """Get hybrid fuzzing summary statistics.

    Returns a dictionary with aggregated hybrid stats including:
    - concolic execution statistics
    - taint tracking statistics
    - trigger counts by type
    - effectiveness metrics
    """
    summary = load_summary(telemetry_dir)
    if not summary.get("hybrid_enabled"):
        return {
            "hybrid_enabled": False,
            "message": "Hybrid fuzzing was not enabled for this session",
        }

    hybrid_stats = summary.get("hybrid_stats", {})
    hybrid_summary = summary.get("hybrid_summary", {})

    # Load hybrid samples for detailed analysis
    hybrid_samples = load_hybrid_samples(telemetry_dir)

    # Count triggers by type
    trigger_counts = {
        "automatic": 0,
        "stagnation": 0,
        "manual": 0,
    }
    for sample in hybrid_samples:
        trigger = sample.get("trigger", "automatic")
        if trigger in trigger_counts:
            trigger_counts[trigger] += 1

    # Calculate effectiveness metrics
    concolic = hybrid_stats.get("concolic", {})
    taint = hybrid_stats.get("taint", {})

    concolic_effectiveness = 0.0
    if concolic.get("runs", 0) > 0:
        concolic_effectiveness = (
            concolic.get("coverage_contributions", 0) /
            max(1, concolic.get("inputs_generated", 1))
        )

    taint_effectiveness = 0.0
    if taint.get("analyses", 0) > 0:
        taint_effectiveness = (
            taint.get("guided_mutations", 0) /
            max(1, taint.get("hot_bytes_identified", 1))
        )

    return {
        "hybrid_enabled": True,
        "mode": hybrid_stats.get("mode", "unknown"),
        "concolic_enabled": hybrid_stats.get("concolic_enabled", False),
        "taint_enabled": hybrid_stats.get("taint_enabled", False),
        "laf_enabled": hybrid_stats.get("laf_enabled", False),
        "concolic_stats": concolic,
        "taint_stats": taint,
        "trigger_counts": trigger_counts,
        "total_hybrid_cycles": len(hybrid_samples),
        "effectiveness": {
            "concolic_coverage_rate": round(concolic_effectiveness, 3),
            "taint_mutation_rate": round(taint_effectiveness, 3),
        },
        "summary": hybrid_summary,
    }


def merge_hybrid_stats(
    base: HybridStats,
    other: HybridStats,
) -> HybridStats:
    """Merge two HybridStats instances (useful for multi-instance fuzzing).

    Args:
        base: Base hybrid stats to merge into
        other: Other hybrid stats to merge from

    Returns:
        New HybridStats instance with merged values
    """
    merged = HybridStats(
        mode=base.mode,
        concolic_enabled=base.concolic_enabled or other.concolic_enabled,
        taint_enabled=base.taint_enabled or other.taint_enabled,
        laf_enabled=base.laf_enabled or other.laf_enabled,
        stagnation_triggers=base.stagnation_triggers + other.stagnation_triggers,
        manual_triggers=base.manual_triggers + other.manual_triggers,
    )

    # Merge concolic stats
    merged.concolic = ConcolicStats(
        runs=base.concolic.runs + other.concolic.runs,
        inputs_generated=base.concolic.inputs_generated + other.concolic.inputs_generated,
        coverage_contributions=base.concolic.coverage_contributions + other.concolic.coverage_contributions,
        constraints_collected=base.concolic.constraints_collected + other.concolic.constraints_collected,
        constraints_solved=base.concolic.constraints_solved + other.concolic.constraints_solved,
        solver_time_total_ms=base.concolic.solver_time_total_ms + other.concolic.solver_time_total_ms,
        last_run=max(
            base.concolic.last_run or "",
            other.concolic.last_run or ""
        ) or None,
    )

    # Merge taint stats
    merged.taint = TaintStats(
        analyses=base.taint.analyses + other.taint.analyses,
        hot_bytes_identified=base.taint.hot_bytes_identified + other.taint.hot_bytes_identified,
        guided_mutations=base.taint.guided_mutations + other.taint.guided_mutations,
        sink_hits_total=base.taint.sink_hits_total + other.taint.sink_hits_total,
        unique_sinks_reached=max(base.taint.unique_sinks_reached, other.taint.unique_sinks_reached),
        last_run=max(
            base.taint.last_run or "",
            other.taint.last_run or ""
        ) or None,
    )

    return merged
