#!/usr/bin/env python3
"""
scripts/validation/run_validation.py

Standalone runner script for the PHISHGUARD Automated Comprehensive Validation Campaign.
Executes pytest across tests/validation, generates real-time stdout metrics,
and ensures reports/validation/ outputs (JSON, CSV, MD, HTML) are refreshed.
"""

import sys
import subprocess
import os
from pathlib import Path


def main():
    root_dir = Path(__file__).resolve().parent.parent.parent
    os.chdir(root_dir)

    print("================================================================")
    print("      PHISHGUARD AUTOMATED COMPREHENSIVE VALIDATION RUNNER      ")
    print("================================================================")
    print(f"Working Directory: {root_dir}")
    print("Executing complete test suite across 17 validation domains...")
    print("----------------------------------------------------------------")

    cmd = [
        sys.executable,
        "-m",
        "pytest",
        "tests/validation",
        "-v",
        "--tb=short"
    ]

    result = subprocess.run(cmd)

    print("----------------------------------------------------------------")
    if result.returncode == 0:
        print("[SUCCESS] All validation tests completed successfully (100% pass rate on runnable tests).")
    else:
        print(f"[WARNING] Validation completed with return code {result.returncode}.")

    report_dir = root_dir / "reports" / "validation"
    if report_dir.exists():
        print(f"\nGenerated Validation Artifacts in: {report_dir}")
        for path in sorted(report_dir.glob("latest.*")):
            print(f"  - {path.name} ({path.stat().st_size} bytes)")

    print("================================================================")
    return result.returncode


if __name__ == "__main__":
    sys.exit(main())
