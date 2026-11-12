#!/usr/bin/env python3
"""Runs the soundness tests of every variant and summarizes them.

  credentials/.venv/bin/python tests/soundness.py [SUITE ...] [--quiet]

SUITE is any of iso, longfellow, vega (default: all of them):
  iso         implementations/iso/common/test_soundness.py   base, sha256-iso, sha512-iso,
                                                              poseidon-iso and the shared library
  longfellow  implementations/longfellow/test_soundness.py
  vega        implementations/vega/test_soundness.py
Each suite prints a PASS or FAIL line per test; --quiet shows only the failures and the summary.
The suites import the credentials' packages, so run this with the Python of credentials/.venv.
Exits with 1 if any test fails or a suite does not complete.
"""

import argparse
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SUITES = {
    "iso": ROOT / "implementations/iso/common/test_soundness.py",
    "longfellow": ROOT / "implementations/longfellow/test_soundness.py",
    "vega": ROOT / "implementations/vega/test_soundness.py",
}


def run(name, script, quiet):
    print(f"\n######## {name} ({script.relative_to(ROOT)})", flush=True)
    start = time.perf_counter()
    proc = subprocess.Popen([sys.executable, str(script)], cwd=script.parent,
                            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    passed = failed = 0
    tail = []
    for line in proc.stdout:
        passed += line.startswith("PASS")
        failed += line.startswith("FAIL")
        tail = (tail + [line])[-20:]
        if not quiet or line.startswith("FAIL"):
            print(line, end="", flush=True)
    proc.wait()
    crashed = proc.returncode != 0 and failed == 0
    if crashed:
        print("".join(tail), end="")
    return {"passed": passed, "failed": failed, "crashed": crashed,
            "seconds": time.perf_counter() - start}


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("suites", nargs="*", metavar="SUITE", help=", ".join(SUITES))
    ap.add_argument("--quiet", action="store_true", help="show only failures and the summary")
    args = ap.parse_args()
    for s in args.suites:
        if s not in SUITES:
            ap.error(f"unknown suite {s!r}")
    try:
        import cbor2  # noqa: F401
    except ImportError:
        sys.exit("cbor2 is missing: run with credentials/.venv/bin/python")
    results = {n: run(n, SUITES[n], args.quiet) for n in (args.suites or SUITES)}

    print("\n######## summary")
    print(f"{'suite':12} {'passed':>7} {'failed':>7} {'time':>8}")
    for n, r in results.items():
        status = "  did not complete" if r["crashed"] else ""
        print(f"{n:12} {r['passed']:>7} {r['failed']:>7} {r['seconds']:>7.0f}s{status}")
    total_passed = sum(r["passed"] for r in results.values())
    total_failed = sum(r["failed"] for r in results.values())
    print(f"{'total':12} {total_passed:>7} {total_failed:>7}")
    return 1 if total_failed or any(r["crashed"] for r in results.values()) else 0


if __name__ == "__main__":
    sys.exit(main())
