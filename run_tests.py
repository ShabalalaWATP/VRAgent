#!/usr/bin/env python3
"""
VRAgent Test Runner
Run Phase 1 implementation tests
"""

import sys
import subprocess
from pathlib import Path


def run_tests():
    """Run all Phase 1 tests"""
    print("=" * 70)
    print("VRAgent Phase 1 Test Suite")
    print("=" * 70)
    print()

    # Test files
    tests = [
        "backend/tests/test_health.py",
        "backend/tests/test_resource_limits.py",
        "backend/tests/test_file_validator.py",
        "backend/tests/test_error_handler.py",
    ]

    results = {}

    for test_file in tests:
        test_path = Path(test_file)

        if not test_path.exists():
            print(f"⚠️  Test file not found: {test_file}")
            results[test_file] = "SKIPPED"
            continue

        print(f"\n{'=' * 70}")
        print(f"Running: {test_file}")
        print(f"{'=' * 70}\n")

        try:
            # Run pytest
            result = subprocess.run(
                [sys.executable, "-m", "pytest", str(test_path), "-v", "--tb=short"],
                capture_output=False,
                text=True
            )

            if result.returncode == 0:
                results[test_file] = "PASSED"
                print(f"\n✅ {test_file}: PASSED")
            else:
                results[test_file] = "FAILED"
                print(f"\n❌ {test_file}: FAILED")

        except Exception as e:
            results[test_file] = "ERROR"
            print(f"\n💥 {test_file}: ERROR - {e}")

    # Summary
    print(f"\n\n{'=' * 70}")
    print("Test Summary")
    print(f"{'=' * 70}\n")

    passed = sum(1 for r in results.values() if r == "PASSED")
    failed = sum(1 for r in results.values() if r == "FAILED")
    errors = sum(1 for r in results.values() if r == "ERROR")
    skipped = sum(1 for r in results.values() if r == "SKIPPED")

    for test_file, result in results.items():
        status_icon = {
            "PASSED": "✅",
            "FAILED": "❌",
            "ERROR": "💥",
            "SKIPPED": "⏭️ "
        }.get(result, "?")

        print(f"{status_icon} {test_file}: {result}")

    print()
    print(f"Total: {len(results)} tests")
    print(f"  ✅ Passed:  {passed}")
    print(f"  ❌ Failed:  {failed}")
    print(f"  💥 Errors:  {errors}")
    print(f"  ⏭️  Skipped: {skipped}")
    print()

    # Exit code
    if failed > 0 or errors > 0:
        print("❌ Some tests failed!")
        return 1
    elif skipped == len(results):
        print("⚠️  All tests were skipped!")
        return 1
    else:
        print("✅ All tests passed!")
        return 0


if __name__ == "__main__":
    sys.exit(run_tests())
