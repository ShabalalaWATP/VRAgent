#!/usr/bin/env python3
"""
Smoke test for the Dynamic Security Scanner API.

Requires an API token with scan permissions. Provide via --token or VRAGENT_TOKEN.
"""

import argparse
import json
import os
import sys
import time
import urllib.error
import urllib.request


def request_json(method, url, data=None, token=None):
    headers = {"Content-Type": "application/json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    body = None
    if data is not None:
        body = json.dumps(data).encode("utf-8")
    req = urllib.request.Request(url, data=body, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            raw = resp.read().decode("utf-8")
            return json.loads(raw) if raw else {}
    except urllib.error.HTTPError as exc:
        raw = exc.read().decode("utf-8")
        raise RuntimeError(f"HTTP {exc.code}: {raw or exc.reason}") from exc
    except urllib.error.URLError as exc:
        raise RuntimeError(f"Request failed: {exc.reason}") from exc


def main():
    parser = argparse.ArgumentParser(description="Run a minimal Dynamic Scanner smoke test.")
    parser.add_argument("--base-url", default="http://localhost:8000", help="Backend base URL.")
    parser.add_argument("--target", default="http://localhost:8000/health", help="Target URL or host to scan.")
    parser.add_argument("--token", default=None, help="API token (or set VRAGENT_TOKEN).")
    parser.add_argument("--scan-name", default="Dynamic Scanner Smoke Test", help="Optional scan name.")
    parser.add_argument("--ai-led", action="store_true", help="Enable AI-led scan planning.")
    parser.add_argument("--poll-interval", type=int, default=5, help="Polling interval in seconds.")
    parser.add_argument("--timeout", type=int, default=900, help="Max seconds to wait for completion.")
    args = parser.parse_args()

    token = args.token or os.getenv("VRAGENT_TOKEN")
    if not token:
        print("Missing API token. Use --token or set VRAGENT_TOKEN.", file=sys.stderr)
        return 2

    start_payload = {
        "scan_name": args.scan_name,
        "target": args.target,
        "ai_led": args.ai_led,
        "aggressive_scan": False,
        "include_openvas": False,
        "include_cve_scan": False,
        "include_exploit_mapping": False,
        "include_directory_enum": False,
        "include_sqlmap": False,
        "include_wapiti": False,
        "include_web_scan": True,
    }

    base_url = args.base_url.rstrip("/")
    start_url = f"{base_url}/dynamic-scan/start"
    status_url = f"{base_url}/dynamic-scan/status"
    results_url = f"{base_url}/dynamic-scan/results"

    print(f"Starting scan against {args.target} ...")
    start_resp = request_json("POST", start_url, data=start_payload, token=token)
    scan_id = start_resp.get("scan_id")
    if not scan_id:
        print(f"Unexpected response: {start_resp}", file=sys.stderr)
        return 1

    print(f"Scan started: {scan_id}")
    deadline = time.time() + args.timeout
    status = None
    while time.time() < deadline:
        status_resp = request_json("GET", f"{status_url}/{scan_id}", token=token)
        status = status_resp.get("status")
        phase = status_resp.get("phase")
        progress = status_resp.get("progress")
        print(f"Status: {status} | Phase: {phase} | Progress: {progress}%")
        if status in {"completed", "failed", "cancelled"}:
            break
        time.sleep(args.poll_interval)

    if status != "completed":
        print(f"Scan ended with status: {status}")
        return 1

    results = request_json("GET", f"{results_url}/{scan_id}", token=token)
    findings = results.get("findings", [])
    severity_counts = {}
    for finding in findings:
        sev = (finding.get("severity") or "info").lower()
        severity_counts[sev] = severity_counts.get(sev, 0) + 1

    print("Scan complete.")
    print(f"Findings: {len(findings)}")
    print(f"Severity breakdown: {severity_counts}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
