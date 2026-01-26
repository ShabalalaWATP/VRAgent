# AFL++ Tools

## Campaign Controller

Analyze telemetry and produce an action plan:

```
python backend\tools\afl_campaign_controller.py --telemetry-dir <telemetry_dir> --target-path <target> --output-dir <afl_output_dir>
```

Generate AI artifacts when stuck:

```
python backend\tools\afl_campaign_controller.py --telemetry-dir <telemetry_dir> --target-path <target> --output-dir <afl_output_dir> --prepare-ai-artifacts
```
