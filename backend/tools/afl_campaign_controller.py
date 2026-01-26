import argparse
import asyncio
import json
import os
from typing import Any, Dict, List

from backend.services.afl_campaign_controller_service import run_campaign_controller


def _write_json(path: str, payload: Dict[str, Any]):
    with open(path, "w", encoding="utf-8") as handle:
        json.dump(payload, handle, indent=2, ensure_ascii=True)


async def _run_controller(args: argparse.Namespace) -> Dict[str, Any]:
    return await run_campaign_controller(
        telemetry_dir=args.telemetry_dir,
        output_dir=args.output_dir,
        target_path=args.target_path,
        queue_dir=args.queue_dir,
        crashes_dir=args.crashes_dir,
        seed_dir=args.seed_dir,
        session_id=args.session_id,
        max_samples=args.max_samples,
        max_entries=args.max_entries,
        auto_prepare_ai_artifacts=args.prepare_ai_artifacts,
        ai_artifacts_dir=args.artifacts_dir,
        ai_seed_count=args.ai_seed_count,
        ai_generate_dictionary=not args.ai_no_dictionary,
        ai_include_existing_seeds=not args.ai_no_include_existing_seeds,
        stagnation_seconds=args.stagnation_seconds,
        min_execs_per_sec=args.min_execs_per_sec,
        min_coverage_gain=args.min_coverage_gain,
        auto_apply_actions=args.auto_apply_actions,
        action_audit_path=args.action_audit_path,
    )


def main() -> int:
    parser = argparse.ArgumentParser(description="AFL++ campaign controller (telemetry-based).")
    parser.add_argument("--telemetry-dir", required=True, help="Telemetry directory with samples.jsonl")
    parser.add_argument("--target-path", required=True, help="Target binary path")
    parser.add_argument("--output-dir", help="AFL++ output directory")
    parser.add_argument("--queue-dir", help="Override AFL++ queue directory")
    parser.add_argument("--crashes-dir", help="Override AFL++ crashes directory")
    parser.add_argument("--seed-dir", help="Seed directory to augment when preparing AI artifacts")
    parser.add_argument("--session-id", help="Optional session identifier")
    parser.add_argument("--max-samples", type=int, default=300, help="Max telemetry samples to load")
    parser.add_argument("--max-entries", type=int, default=200, help="Max corpus/crash entries to load")
    parser.add_argument("--prepare-ai-artifacts", action="store_true", help="Generate AI artifacts when stuck")
    parser.add_argument("--artifacts-dir", help="Output directory for AI artifacts")
    parser.add_argument("--ai-seed-count", type=int, default=10, help="Number of AI seeds to generate")
    parser.add_argument("--ai-no-dictionary", action="store_true", help="Disable AFL dictionary generation")
    parser.add_argument("--ai-no-include-existing-seeds", action="store_true", help="Do not include existing seeds")
    parser.add_argument("--stagnation-seconds", type=int, default=1800, help="Seconds since last path to treat as stuck")
    parser.add_argument("--min-execs-per-sec", type=float, default=10.0, help="Execs/sec threshold for performance alerts")
    parser.add_argument("--min-coverage-gain", type=int, default=1, help="Minimum coverage gain to avoid plateau")
    parser.add_argument("--auto-apply-actions", action="store_true", help="Auto-apply action plan recommendations")
    parser.add_argument("--action-audit-path", help="Path to JSONL audit log for applied actions")
    parser.add_argument("--out", help="Write JSON summary to this path")
    args = parser.parse_args()

    if args.prepare_ai_artifacts and not args.output_dir and not args.artifacts_dir:
        print("Provide --output-dir or --artifacts-dir when preparing AI artifacts.")
        return 1

    result = asyncio.run(_run_controller(args))
    out_path = args.out or os.path.join(args.output_dir or ".", "controller_summary.json")
    _write_json(out_path, result)
    print(f"Controller summary written to {out_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
