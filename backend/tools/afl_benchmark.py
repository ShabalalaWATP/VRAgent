import argparse
import asyncio
import json
import os
import sys
import time
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

import yaml

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from backend.services.binary_fuzzer_service import AflPlusPlusFuzzer
from backend.services.afl_ai_artifacts_service import prepare_ai_artifacts


def _load_config(path: str) -> Dict[str, Any]:
    with open(path, "r", encoding="utf-8") as handle:
        if path.endswith((".yaml", ".yml")):
            return yaml.safe_load(handle)
        return json.load(handle)


def _merge_case(defaults: Dict[str, Any], case: Dict[str, Any]) -> Dict[str, Any]:
    merged = dict(defaults or {})
    merged.update(case or {})
    return merged


def _validate_case(case: Dict[str, Any]) -> List[str]:
    errors = []
    case_id = case.get("id")
    if not case_id:
        errors.append("case.id is required")
    target_path = case.get("target_path")
    if not target_path or not os.path.isfile(target_path):
        errors.append(f"target_path not found: {target_path}")
    seed_dir = case.get("seed_dir")
    if not seed_dir or not os.path.isdir(seed_dir):
        errors.append(f"seed_dir not found: {seed_dir}")
    dict_path = case.get("dictionary_path")
    if dict_path and not os.path.isfile(dict_path):
        errors.append(f"dictionary_path not found: {dict_path}")
    return errors


async def _run_case(
    case: Dict[str, Any],
    run_root: str,
    dry_run: bool,
) -> Dict[str, Any]:
    case_id = case["id"]
    output_dir = os.path.join(run_root, case_id)
    telemetry_dir = os.path.join(output_dir, "telemetry")
    os.makedirs(output_dir, exist_ok=True)

    if dry_run:
        return {
            "id": case_id,
            "status": "dry_run",
            "output_dir": output_dir,
            "telemetry_dir": telemetry_dir,
        }

    input_dir = case["seed_dir"]
    dictionary_path = case.get("dictionary_path")
    ai_artifacts = None
    if case.get("ai_generate_seeds") or case.get("ai_generate_dictionary"):
        ai_artifacts = await prepare_ai_artifacts(
            target_path=case["target_path"],
            input_dir=input_dir,
            artifacts_dir=os.path.join(output_dir, "ai_artifacts"),
            num_seeds=int(case.get("ai_seed_count", 10)),
            include_existing_seeds=bool(case.get("ai_include_existing_seeds", True)),
            generate_dictionary=bool(case.get("ai_generate_dictionary", True)),
            extra_dictionary_entries=case.get("dictionary"),
        )
        input_dir = ai_artifacts.seeds_dir
        if ai_artifacts.dictionary_path:
            dictionary_path = ai_artifacts.dictionary_path

    fuzzer = AflPlusPlusFuzzer(
        target_path=case["target_path"],
        target_args=case.get("target_args", "@@"),
        input_dir=input_dir,
        output_dir=output_dir,
        timeout_ms=int(case.get("timeout_ms", 1000)),
        memory_limit_mb=int(case.get("memory_limit_mb", 256)),
        use_qemu=bool(case.get("use_qemu", True)),
        session_id=case_id,
        output_dir_is_session=True,
        dictionary_path=dictionary_path,
        env_vars=case.get("env") or {},
        extra_afl_flags=case.get("extra_afl_flags") or [],
        qemu_mode=case.get("qemu_mode"),
        persistent_address=case.get("persistent_address"),
        persistent_count=int(case.get("persistent_count", 10000)),
        persistent_hook=case.get("persistent_hook"),
        enable_compcov=bool(case.get("enable_compcov", False)),
        enable_instrim=bool(case.get("enable_instrim", False)),
        telemetry_dir=telemetry_dir,
        telemetry_interval_sec=float(case.get("telemetry_interval_sec", 2.0)),
    )

    max_runtime = case.get("duration_seconds")
    stop_timeout = int(case.get("stop_timeout_seconds", 30))
    start_time = time.time()
    stop_requested = False
    stop_deadline = None
    final_event: Optional[Dict[str, Any]] = None

    async for event in fuzzer.start():
        if event.get("type") == "error":
            final_event = event
            break
        if max_runtime and not stop_requested:
            if time.time() - start_time >= max_runtime:
                stop_requested = True
                stop_deadline = time.time() + stop_timeout
                await fuzzer.stop()
        if stop_requested and stop_deadline and time.time() >= stop_deadline:
            final_event = {
                "type": "error",
                "error": f"Stop timeout after {stop_timeout} seconds",
            }
            break
        if event.get("type") == "session_end":
            final_event = event
            break

    duration_sec = time.time() - start_time
    stats = final_event.get("stats") if final_event else None
    status = "completed"
    error = None
    if final_event and final_event.get("type") == "error":
        status = "error"
        error = final_event.get("error")

    return {
        "id": case_id,
        "status": status,
        "error": error,
        "duration_sec": round(duration_sec, 3),
        "output_dir": output_dir,
        "telemetry_dir": telemetry_dir,
        "stats": stats,
        "ai_artifacts_dir": ai_artifacts.artifacts_dir if ai_artifacts else None,
        "ai_manifest_path": ai_artifacts.manifest_path if ai_artifacts else None,
    }


async def _run_benchmark(config: Dict[str, Any], dry_run: bool) -> Dict[str, Any]:
    defaults = config.get("defaults") or {}
    cases = config.get("cases") or []
    output_root = config.get("output_root") or os.path.join("benchmarks", "runs")
    run_id = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    run_root = os.path.join(output_root, run_id)
    os.makedirs(run_root, exist_ok=True)

    results = []
    for raw_case in cases:
        case = _merge_case(defaults, raw_case)
        result = await _run_case(case, run_root, dry_run)
        results.append(result)

    summary = {
        "schema_version": 1,
        "run_id": run_id,
        "started_at": datetime.utcnow().isoformat() + "Z",
        "output_root": run_root,
        "case_count": len(results),
        "cases": results,
    }
    summary_path = os.path.join(run_root, "summary.json")
    with open(summary_path, "w", encoding="utf-8") as handle:
        json.dump(summary, handle, indent=2)

    return summary


def main() -> int:
    parser = argparse.ArgumentParser(description="Run AFL++ benchmark suite.")
    parser.add_argument("--config", required=True, help="Path to benchmark config (yaml/json).")
    parser.add_argument("--dry-run", action="store_true", help="Validate config without running.")
    args = parser.parse_args()

    config = _load_config(args.config)
    if not config or "cases" not in config:
        print("Invalid config: expected 'cases' list")
        return 1

    if not args.dry_run:
        availability = AflPlusPlusFuzzer.is_available()
        if not availability.get("installed"):
            print("AFL++ not installed or not found in PATH.")
            return 1

    errors = []
    defaults = config.get("defaults") or {}
    for raw_case in config.get("cases", []):
        case = _merge_case(defaults, raw_case)
        errors.extend(_validate_case(case))

    if errors:
        for err in errors:
            print(f"Config error: {err}")
        return 1

    summary = asyncio.run(_run_benchmark(config, args.dry_run))
    print(f"Benchmark run {summary['run_id']} completed.")
    print(f"Results in: {summary['output_root']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
