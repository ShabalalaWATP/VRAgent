import json
import os
import time
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple

from backend.services.afl_ai_artifacts_service import prepare_ai_artifacts
from backend.services.afl_telemetry_service import (
    build_stats_history,
    list_afl_inputs,
    load_run_metadata,
    load_summary,
)
from backend.services.ai_fuzzer_service import analyze_binary, analyze_coverage_and_advise
from backend.services.binary_fuzzer_service import SmartDictionaryExtractor
from backend.services.agentic_fuzzer_brain import (
    make_agentic_decision,
    analyze_crash_with_ai,
    get_or_create_brain,
    clear_brain,
)


def _extract_coverage_series(stats_history: List[Dict[str, Any]]) -> List[int]:
    values = []
    for item in stats_history:
        value = item.get("total_edges", item.get("paths_total", 0))
        try:
            values.append(int(value))
        except (TypeError, ValueError):
            values.append(0)
    return values


def _iso_utc_now() -> str:
    return datetime.utcnow().isoformat() + "Z"


def _append_jsonl(path: str, payload: Dict[str, Any]) -> Optional[str]:
    try:
        os.makedirs(os.path.dirname(path), exist_ok=True)
    except Exception as e:
        return str(e)
    try:
        line = json.dumps(payload, separators=(",", ":"))
        with open(path, "a", encoding="utf-8") as handle:
            handle.write(line + "\n")
    except Exception as e:
        return str(e)
    return None


def _escape_afl_dictionary_bytes(data: bytes) -> str:
    escaped = []
    for b in data:
        if 32 <= b <= 126 and b not in (34, 92):
            escaped.append(chr(b))
        elif b == 34:
            escaped.append('\\"')
        elif b == 92:
            escaped.append('\\\\')
        else:
            escaped.append(f"\\x{b:02x}")
    return "".join(escaped)


def _normalize_dictionary_entries(
    entries: List[Any],
    max_entries: int,
    max_entry_bytes: int = 256,
) -> List[bytes]:
    seen: set = set()
    normalized: List[bytes] = []
    for entry in entries:
        if entry is None:
            continue
        if isinstance(entry, bytes):
            data = entry
        else:
            data = str(entry).encode("utf-8", errors="replace")
        if not data:
            continue
        if len(data) > max_entry_bytes:
            data = data[:max_entry_bytes]
        if data in seen:
            continue
        seen.add(data)
        normalized.append(data)
        if len(normalized) >= max_entries:
            break
    return normalized


def _write_afl_dictionary_file(entries: List[bytes], output_dir: str) -> Optional[str]:
    if not entries:
        return None
    os.makedirs(output_dir, exist_ok=True)
    dict_path = os.path.join(output_dir, "afl_dictionary.txt")
    try:
        with open(dict_path, "w", encoding="utf-8") as handle:
            for idx, entry in enumerate(entries):
                escaped = _escape_afl_dictionary_bytes(entry)
                handle.write(f"key{idx}=\"{escaped}\"\n")
    except Exception:
        return None
    return dict_path


def _generate_dictionary_artifact(
    target_path: str,
    output_dir: str,
    max_entries: int = 1000,
) -> Tuple[Optional[str], List[str], int]:
    warnings: List[str] = []
    entries: List[Any] = []
    try:
        extractor = SmartDictionaryExtractor(target_path, max_entries=max_entries)
        entries.extend([entry.value for entry in extractor.extract_all()])
    except Exception as e:
        warnings.append(f"Smart dictionary extraction failed: {e}")

    if not entries:
        try:
            binary_info = analyze_binary(target_path)
            entries.extend(binary_info.strings)
        except Exception as e:
            warnings.append(f"Binary analysis failed: {e}")

    normalized = _normalize_dictionary_entries(entries, max_entries=max_entries)
    dict_path = _write_afl_dictionary_file(normalized, output_dir)
    if not dict_path:
        return None, warnings, 0
    return dict_path, warnings, len(normalized)


def _build_next_run_config(
    target_path: str,
    run_metadata: Dict[str, Any],
    output_dir: Optional[str],
    seed_dir: Optional[str],
    queue_dir: Optional[str],
) -> Dict[str, Any]:
    extra_flags = run_metadata.get("extra_afl_flags")
    if not isinstance(extra_flags, list):
        extra_flags = []
    base_input = run_metadata.get("input_dir") or seed_dir or queue_dir
    return {
        "target_path": target_path,
        "target_args": run_metadata.get("target_args") or "@@",
        "input_dir": base_input,
        "output_dir": output_dir or run_metadata.get("output_dir"),
        "timeout_ms": run_metadata.get("timeout_ms"),
        "memory_limit_mb": run_metadata.get("memory_limit_mb"),
        "use_qemu": run_metadata.get("use_qemu"),
        "qemu_mode": run_metadata.get("qemu_mode"),
        "dictionary_path": run_metadata.get("dictionary_path"),
        "extra_afl_flags": list(extra_flags),
        "env_vars": {},
    }


def _time_since(value: Optional[float], now: float) -> Optional[float]:
    if value is None:
        return None
    try:
        val = float(value)
    except (TypeError, ValueError):
        return None
    if val <= 0:
        return None
    if val > 1_000_000_000:
        return max(0.0, now - val)
    return max(0.0, val)


def _latest_stat(stats_history: List[Dict[str, Any]]) -> Dict[str, Any]:
    return stats_history[-1] if stats_history else {}


def _build_action_plan(
    advice: Any,
    run_metadata: Dict[str, Any],
    stats_history: List[Dict[str, Any]],
    stagnation_seconds: int,
    min_execs_per_sec: float,
    min_coverage_gain: int,
) -> Dict[str, Any]:
    latest = _latest_stat(stats_history)
    now = time.time()

    coverage_series = _extract_coverage_series(stats_history)
    coverage_gain = 0
    if len(coverage_series) >= 2:
        coverage_gain = coverage_series[-1] - coverage_series[0]

    last_path_age = _time_since(latest.get("last_path_time"), now)
    last_crash_age = _time_since(latest.get("last_crash_time"), now)

    execs_per_sec = latest.get("execs_per_sec", 0) or 0
    unique_crashes = latest.get("unique_crashes", 0) or 0
    map_coverage = latest.get("map_coverage")

    signals = {
        "coverage_gain": coverage_gain,
        "last_path_age_sec": last_path_age,
        "last_crash_age_sec": last_crash_age,
        "execs_per_sec": execs_per_sec,
        "unique_crashes": unique_crashes,
        "map_coverage": map_coverage,
        "no_new_paths": coverage_gain < min_coverage_gain,
        "stale_paths": bool(last_path_age and last_path_age > stagnation_seconds),
        "stale_crashes": bool(last_crash_age and last_crash_age > stagnation_seconds),
        "low_execs_per_sec": execs_per_sec and execs_per_sec < min_execs_per_sec,
    }

    actions = []

    if advice.is_stuck or signals["no_new_paths"] or signals["stale_paths"]:
        actions.append({
            "action": "generate_ai_artifacts",
            "priority": "high",
            "reason": advice.stuck_reason or "Coverage not improving",
        })

    if signals["low_execs_per_sec"]:
        actions.append({
            "action": "tune_performance",
            "priority": "medium",
            "reason": f"Low execs/sec ({execs_per_sec})",
            "details": {
                "suggestions": [
                    "Use instrumented build or persistent mode",
                    "Reduce timeout or input size",
                ]
            },
        })

    if run_metadata:
        if not run_metadata.get("dictionary_path"):
            actions.append({
                "action": "add_dictionary",
                "priority": "medium",
                "reason": "No dictionary configured",
            })

        if run_metadata.get("use_qemu") and not run_metadata.get("qemu_mode"):
            actions.append({
                "action": "enable_compcov",
                "priority": "medium",
                "reason": "QEMU mode without comparison coverage",
                "details": {
                    "qemu_mode": "compcov",
                },
            })

    if unique_crashes == 0 and coverage_series and coverage_series[-1] > 0:
        actions.append({
            "action": "increase_mutation_intensity",
            "priority": "low",
            "reason": "Coverage growth without crashes",
        })

    # ==========================================================================
    # HYBRID FUZZING ACTIONS - Phase 1 Advanced Features
    # ==========================================================================

    # Trigger concolic execution on coverage stagnation
    if advice.is_stuck or signals["stale_paths"]:
        stagnation_time = signals.get("last_path_age_sec", 0)
        actions.append({
            "action": "trigger_concolic_cycle",
            "priority": "high",
            "reason": f"Coverage stagnation for {int(stagnation_time)}s - concolic may find new paths",
            "details": {
                "stagnation_seconds": stagnation_time,
                "technique": "concolic_execution",
                "expected_outcome": "Generate inputs that solve complex constraints",
            },
        })

    # Trigger taint analysis on crashes to identify hot bytes
    if unique_crashes > 0 and signals.get("no_new_paths"):
        actions.append({
            "action": "trigger_taint_analysis",
            "priority": "high",
            "reason": f"Found {unique_crashes} crashes but coverage stalled - taint analysis can identify hot bytes",
            "details": {
                "crash_count": unique_crashes,
                "technique": "taint_tracking",
                "expected_outcome": "Identify input bytes that reach security-sensitive functions",
            },
        })

    # Suggest LAF-Intel if not instrumented and coverage is low
    if run_metadata:
        laf_available = run_metadata.get("laf_available", False)
        laf_instrumented = run_metadata.get("laf_instrumented", False)

        if laf_available and not laf_instrumented:
            actions.append({
                "action": "rebuild_with_laf_intel",
                "priority": "medium",
                "reason": "LAF-Intel available but target not instrumented - can improve coverage",
                "details": {
                    "technique": "laf_intel",
                    "expected_outcome": "Split complex comparisons for better coverage feedback",
                },
            })

        # Suggest hybrid mode if concolic/taint available but not enabled
        hybrid_available = run_metadata.get("hybrid_available", False)
        hybrid_enabled = run_metadata.get("hybrid_enabled", False)

        if hybrid_available and not hybrid_enabled and (advice.is_stuck or signals["stale_paths"]):
            actions.append({
                "action": "enable_hybrid_fuzzing",
                "priority": "high",
                "reason": "Hybrid fuzzing available - enables automatic concolic/taint triggering",
                "details": {
                    "techniques": ["concolic_execution", "taint_tracking", "laf_intel"],
                    "expected_outcome": "Automatically solve constraints and target hot bytes",
                },
            })

    return {
        "signals": signals,
        "actions": actions,
    }


async def run_campaign_controller(
    telemetry_dir: str,
    output_dir: Optional[str],
    target_path: str,
    queue_dir: Optional[str] = None,
    crashes_dir: Optional[str] = None,
    seed_dir: Optional[str] = None,
    session_id: Optional[str] = None,
    max_samples: int = 300,
    max_entries: int = 200,
    auto_prepare_ai_artifacts: bool = False,
    ai_artifacts_dir: Optional[str] = None,
    ai_seed_count: int = 10,
    ai_generate_dictionary: bool = True,
    ai_include_existing_seeds: bool = True,
    stagnation_seconds: int = 1800,
    min_execs_per_sec: float = 10.0,
    min_coverage_gain: int = 1,
    auto_apply_actions: bool = False,
    action_audit_path: Optional[str] = None,
    use_agentic_ai: bool = True,  # NEW: Use agentic AI brain for decisions
) -> Dict[str, Any]:
    """
    Run the campaign controller to analyze fuzzing progress and decide actions.

    Args:
        use_agentic_ai: If True, uses the AI brain for strategic decisions.
                       If False, falls back to rule-based heuristics.
    """
    stats_history = build_stats_history(telemetry_dir, max_samples=max_samples)
    run_metadata = load_run_metadata(telemetry_dir)
    summary = load_summary(telemetry_dir)

    queue_dir = queue_dir or (os.path.join(output_dir, "default", "queue") if output_dir else None)
    crashes_dir = crashes_dir or (os.path.join(output_dir, "default", "crashes") if output_dir else None)

    corpus = list_afl_inputs(queue_dir, limit=max_entries) if queue_dir else []
    crashes = list_afl_inputs(crashes_dir, limit=max_entries, skip_names={"README.txt"}) if crashes_dir else []

    # Prepare crash data for agentic AI
    crash_data_for_ai = [
        {
            "id": c.get("name", f"crash_{i}"),
            "size": c.get("size", 0),
            "crash_type": c.get("crash_type", "unknown"),
        }
        for i, c in enumerate(crashes)
    ]

    corpus_info = {
        "size": len(corpus),
        "total_bytes": sum(c.get("size", 0) for c in corpus),
    }

    # Use agentic AI brain or fall back to heuristics
    agentic_result = None
    if use_agentic_ai:
        try:
            agentic_result = await make_agentic_decision(
                session_id=session_id or "controller",
                target_path=target_path,
                stats_history=stats_history,
                current_crashes=crash_data_for_ai,
                corpus_info=corpus_info,
                run_metadata=run_metadata,
            )
        except Exception as e:
            import logging
            logging.getLogger(__name__).warning(f"Agentic AI failed, falling back to heuristics: {e}")

    # Always get heuristic advice (for backwards compatibility and comparison)
    advice = await analyze_coverage_and_advise(
        session_id=session_id or "controller",
        stats_history=stats_history,
        current_corpus=corpus,
        crashes=crashes,
    )

    # If agentic AI provided decisions, convert them to action plan format
    if agentic_result and agentic_result.get("decisions"):
        # Convert agentic decisions to legacy action format
        agentic_actions = []
        for decision in agentic_result["decisions"]:
            action_name = decision["action"]
            # Map agentic actions to legacy action names
            action_mapping = {
                "generate_smart_seeds": "generate_ai_artifacts",
                "generate_dictionary": "add_dictionary",
                "enable_compcov": "enable_compcov",
                "increase_mutation_depth": "increase_mutation_intensity",
                "reduce_timeout": "tune_performance",
                "focus_on_crashes": "generate_ai_artifacts",  # Re-seed from crashes
                "try_structure_aware": "generate_ai_artifacts",
                "restart_with_queue": "generate_ai_artifacts",
                "analyze_crashes": "analyze_crashes",
            }
            mapped_action = action_mapping.get(action_name, action_name)

            agentic_actions.append({
                "action": mapped_action,
                "priority": decision["priority"],
                "reason": decision["reasoning"],
                "ai_confidence": decision["confidence"],
                "ai_expected_outcome": decision["expected_outcome"],
                "ai_alternatives": decision["alternatives_considered"],
                "source": "agentic_ai",
            })

        plan = {
            "signals": {
                "agentic_ai_used": True,
                "ai_available": agentic_result.get("ai_available", False),
                "cycle_count": agentic_result.get("cycle_count", 0),
                "memory_count": agentic_result.get("memory_count", 0),
            },
            "actions": agentic_actions,
            "reasoning_summary": agentic_result.get("reasoning_summary", ""),
        }
    else:
        # Fall back to rule-based plan
        plan = _build_action_plan(
            advice=advice,
            run_metadata=run_metadata,
            stats_history=stats_history,
            stagnation_seconds=stagnation_seconds,
            min_execs_per_sec=min_execs_per_sec,
            min_coverage_gain=min_coverage_gain,
        )
        plan["signals"]["agentic_ai_used"] = False

    ai_artifacts_info = None
    applied_actions: List[Dict[str, Any]] = []
    next_run_config: Optional[Dict[str, Any]] = None
    resolved_audit_path = None

    if auto_apply_actions:
        next_run_config = _build_next_run_config(
            target_path=target_path,
            run_metadata=run_metadata,
            output_dir=output_dir,
            seed_dir=seed_dir,
            queue_dir=queue_dir,
        )

        artifacts_dir = ai_artifacts_dir
        if not artifacts_dir:
            if output_dir:
                artifacts_dir = os.path.join(output_dir, "ai_artifacts")
            else:
                artifacts_dir = os.path.join(telemetry_dir, "ai_artifacts")

        resolved_audit_path = action_audit_path or os.path.join(telemetry_dir, "campaign_actions.jsonl")

        seed_source_dir = seed_dir or queue_dir or next_run_config.get("input_dir")

        for action in plan["actions"]:
            action_name = action.get("action")
            action_result = {
                "action": action_name,
                "priority": action.get("priority"),
                "reason": action.get("reason"),
                "applied_at": _iso_utc_now(),
                "status": "skipped",
            }
            try:
                if action_name == "generate_ai_artifacts":
                    if not artifacts_dir:
                        action_result["status"] = "failed"
                        action_result["error"] = "Missing artifacts_dir or output_dir"
                    else:
                        artifacts = await prepare_ai_artifacts(
                            target_path=target_path,
                            input_dir=seed_source_dir,
                            artifacts_dir=artifacts_dir,
                            num_seeds=ai_seed_count,
                            include_existing_seeds=ai_include_existing_seeds,
                            generate_dictionary=ai_generate_dictionary,
                        )
                        ai_artifacts_info = {
                            "artifacts_dir": artifacts.artifacts_dir,
                            "seed_dir": artifacts.seeds_dir,
                            "dictionary_path": artifacts.dictionary_path,
                            "manifest_path": artifacts.manifest_path,
                            "warnings": artifacts.warnings,
                        }
                        next_run_config["input_dir"] = artifacts.seeds_dir
                        if artifacts.dictionary_path:
                            next_run_config["dictionary_path"] = artifacts.dictionary_path
                        action_result["status"] = "applied"
                        action_result["outputs"] = {
                            "artifacts_dir": artifacts.artifacts_dir,
                            "seed_dir": artifacts.seeds_dir,
                            "dictionary_path": artifacts.dictionary_path,
                            "manifest_path": artifacts.manifest_path,
                            "warnings": artifacts.warnings,
                        }

                elif action_name == "add_dictionary":
                    if not ai_generate_dictionary:
                        action_result["status"] = "skipped"
                        action_result["reason"] = "Dictionary generation disabled"
                    elif next_run_config.get("dictionary_path"):
                        action_result["status"] = "skipped"
                        action_result["reason"] = "Dictionary already configured"
                    else:
                        dict_path, warnings, entry_count = _generate_dictionary_artifact(
                            target_path=target_path,
                            output_dir=artifacts_dir or telemetry_dir,
                        )
                        if dict_path:
                            next_run_config["dictionary_path"] = dict_path
                            action_result["status"] = "applied"
                            action_result["outputs"] = {
                                "dictionary_path": dict_path,
                                "dictionary_entries": entry_count,
                                "warnings": warnings,
                            }
                        else:
                            action_result["status"] = "failed"
                            action_result["error"] = "Failed to generate dictionary"
                            action_result["warnings"] = warnings

                elif action_name == "enable_compcov":
                    if not next_run_config.get("use_qemu"):
                        action_result["status"] = "skipped"
                        action_result["reason"] = "QEMU mode not enabled"
                    else:
                        next_run_config["enable_compcov"] = True
                        next_run_config["qemu_mode"] = "compcov"
                        action_result["status"] = "applied"
                        action_result["updates"] = {
                            "enable_compcov": True,
                            "qemu_mode": "compcov",
                        }

                elif action_name == "increase_mutation_intensity":
                    env_vars = next_run_config.setdefault("env_vars", {})
                    if "AFL_HAVOC_MULT" in env_vars:
                        action_result["status"] = "skipped"
                        action_result["reason"] = "AFL_HAVOC_MULT already set"
                    else:
                        env_vars["AFL_HAVOC_MULT"] = "2"
                        action_result["status"] = "applied"
                        action_result["updates"] = {"env_vars": {"AFL_HAVOC_MULT": "2"}}

                elif action_name == "tune_performance":
                    flags = next_run_config.get("extra_afl_flags") or []
                    if "-d" in flags:
                        action_result["status"] = "skipped"
                        action_result["reason"] = "Deterministic stage already disabled"
                    else:
                        flags.append("-d")
                        next_run_config["extra_afl_flags"] = flags
                        action_result["status"] = "applied"
                        action_result["updates"] = {"extra_afl_flags": flags}

                else:
                    action_result["status"] = "skipped"
                    action_result["reason"] = "Unknown action"
            except Exception as e:
                action_result["status"] = "failed"
                action_result["error"] = str(e)

            audit_payload = {
                "ts": _iso_utc_now(),
                "action": action_name,
                "status": action_result["status"],
                "reason": action_result.get("reason"),
                "priority": action_result.get("priority"),
                "session_id": session_id or "controller",
                "telemetry_dir": telemetry_dir,
                "target_path": target_path,
                "outputs": action_result.get("outputs"),
                "updates": action_result.get("updates"),
                "error": action_result.get("error"),
            }
            audit_error = _append_jsonl(resolved_audit_path, audit_payload)
            if audit_error:
                action_result["audit_error"] = audit_error
            applied_actions.append(action_result)

    result = {
        "schema_version": 2,  # Updated for agentic AI
        "session_id": session_id or "controller",
        "telemetry_dir": telemetry_dir,
        "output_dir": output_dir,
        "run_metadata": run_metadata,
        "summary": summary,
        "stats_samples": len(stats_history),
        "corpus_entries": len(corpus),
        "crash_entries": len(crashes),
        "coverage_trend": advice.coverage_trend,
        "is_stuck": advice.is_stuck,
        "stuck_reason": advice.stuck_reason,
        "recommendations": advice.recommendations,
        "mutation_adjustments": advice.mutation_adjustments,
        "priority_areas": advice.priority_areas,
        "action_plan": plan,
        # Agentic AI information
        "agentic_ai": {
            "enabled": use_agentic_ai,
            "used": plan.get("signals", {}).get("agentic_ai_used", False),
            "ai_available": agentic_result.get("ai_available", False) if agentic_result else False,
            "cycle_count": agentic_result.get("cycle_count", 0) if agentic_result else 0,
            "memory_count": agentic_result.get("memory_count", 0) if agentic_result else 0,
            "reasoning_summary": plan.get("reasoning_summary", "") if agentic_result else "",
        },
    }

    if auto_apply_actions:
        result["applied_actions"] = applied_actions
        result["next_run_config"] = next_run_config or {}
        result["action_audit_path"] = resolved_audit_path

    if not auto_apply_actions and auto_prepare_ai_artifacts and (advice.is_stuck or plan.get("signals", {}).get("no_new_paths", False)):
        artifacts_dir = ai_artifacts_dir or os.path.join(output_dir or ".", "ai_artifacts")
        artifacts = await prepare_ai_artifacts(
            target_path=target_path,
            input_dir=seed_dir or queue_dir,
            artifacts_dir=artifacts_dir,
            num_seeds=ai_seed_count,
            include_existing_seeds=ai_include_existing_seeds,
            generate_dictionary=ai_generate_dictionary,
        )
        ai_artifacts_info = {
            "artifacts_dir": artifacts.artifacts_dir,
            "seed_dir": artifacts.seeds_dir,
            "dictionary_path": artifacts.dictionary_path,
            "manifest_path": artifacts.manifest_path,
            "warnings": artifacts.warnings,
        }

    if ai_artifacts_info:
        result["ai_artifacts"] = ai_artifacts_info

    return result
