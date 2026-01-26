# AFL++ Benchmark Harness

This harness runs repeatable AFL++ baselines and writes telemetry artifacts for later analysis.

## Quick start

1) Copy the example config and fill in real targets:

```
copy benchmarks\config.example.yaml benchmarks\config.yaml
```

2) Run a dry validation:

```
python backend\tools\afl_benchmark.py --config benchmarks\config.yaml --dry-run
```

3) Run the benchmark:

```
python backend\tools\afl_benchmark.py --config benchmarks\config.yaml
```

## Output

Each run is written to:

```
benchmarks\runs\<timestamp>\
```

Each case has:
- AFL++ output directories (queue/crashes/hangs)
- Telemetry artifacts in `telemetry\` (`run.json`, `samples.jsonl`, `summary.json`)
- `summary.json` at the run root with per-case results

Telemetry sampling interval defaults to 2 seconds and can be overridden per case.

AI artifact generation can be enabled per case with:
- `ai_generate_seeds`
- `ai_seed_count`
- `ai_generate_dictionary`
- `ai_include_existing_seeds`
