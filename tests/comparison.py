#!/usr/bin/env python3
"""Compares the circuit variants and their ISO/IEC 18013-5 versions on this machine.

The variants are sha256, sha512, poseidon and base, each next to its -iso version (the hash
commitment is the MSO digest of IssuerSignedItemBytes), and longfellow. Each -iso version is
compared with its counterpart, and longfellow with the ISO-compliant versions (sha256-iso and
sha512-iso). For each circuit it reports the number of gates (bb gates) and the average time
to generate the witness (nargo execute), the proof (bb prove) and to verify it
(bb verify). The circuits are copied to a temporary directory, so the target/
folders in the repository are left untouched.

Usage: python3 tests/comparison.py [SCENARIO ...] [--variants V ...] [--runs N]
       SCENARIO is one of int, age, nationality, str (default: all of them)
       V is any of the variants below (default: all of them)
Requires: nargo and bb on the PATH.
"""

import argparse
import json
import shutil
import statistics
import subprocess
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
IMPLEMENTATIONS = ROOT / "implementations"
SCENARIOS = ["int", "age", "nationality", "str"]
VARIANTS = ["sha256", "sha256-iso", "sha512", "sha512-iso", "poseidon", "poseidon-iso",
            "base", "base-iso", "longfellow"]
# Comparison tables printed at the end, as (variant, reference) pairs. poseidon-iso uses a digest
# algorithm that ISO 18013-5 does not allow and base-iso has no digest, so longfellow is compared
# only with the ISO-compliant versions.
ISO_PAIRS = [(f"{v}-iso", v) for v in ["sha256", "sha512", "poseidon", "base"]]
LONGFELLOW_PAIRS = [("longfellow", "sha256-iso"), ("longfellow", "sha512-iso")]


def run(cmd, cwd):
    start = time.perf_counter()
    res = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True)
    elapsed = time.perf_counter() - start
    if res.returncode != 0:
        raise RuntimeError(f"{' '.join(cmd)} failed in {cwd}:\n{res.stdout}{res.stderr}")
    return elapsed, res.stdout


def package_name(path):
    for line in (path / "Nargo.toml").read_text().splitlines():
        key, _, value = line.partition("=")
        if key.strip() == "name":
            return value.strip().strip('"')
    raise ValueError(f"no package name in {path / 'Nargo.toml'}")


def path_dependencies(package):
    """Directories of the local (path = "...") dependencies of a package, recursively."""
    deps = []
    for line in (package / "Nargo.toml").read_text().splitlines():
        if "path" in line and "=" in line:
            rel = line.split("path", 1)[1].split('"')[1]
            dep = (package / rel).resolve()
            deps += [dep] + path_dependencies(dep)
    return deps


def gates(json_path, cwd):
    _, out = run(["bb", "gates", "-b", str(json_path)], cwd)
    return json.loads(out[out.index("{"):])["functions"][0]["circuit_size"]


def benchmark(src, runs):
    with tempfile.TemporaryDirectory() as tmp:
        # Mirror implementations/ so that relative path dependencies (../lib, ../../iso/lib) resolve
        work = Path(tmp) / src.relative_to(IMPLEMENTATIONS)
        for d in [src] + path_dependencies(src):
            shutil.copytree(d, Path(tmp) / d.relative_to(IMPLEMENTATIONS),
                            ignore=shutil.ignore_patterns("target"), dirs_exist_ok=True)
        name = package_name(work)
        circuit, witness = work / "target" / f"{name}.json", work / "target" / f"{name}.gz"

        run(["nargo", "compile"], work)
        n_gates = gates(circuit, work)
        run(["bb", "write_vk", "-b", str(circuit), "-o", "target"], work)

        times = {"execute": [], "prove": [], "verify": []}
        for _ in range(runs):
            times["execute"].append(run(["nargo", "execute"], work)[0])
            times["prove"].append(
                run(["bb", "prove", "-b", str(circuit), "-w", str(witness), "-o", "target"], work)[0])
            times["verify"].append(
                run(["bb", "verify", "-k", "target/vk", "-p", "target/proof",
                     "-i", "target/public_inputs"], work)[0])
        return n_gates, times


def print_table(header, rows):
    """Prints rows as a table, with the first column left-aligned and the others right-aligned."""
    widths = [max(len(str(r[i])) for r in [header] + rows) for i in range(len(header))]
    line = lambda r: "  ".join(str(c).ljust(w) if i == 0 else str(c).rjust(w)
                               for i, (c, w) in enumerate(zip(r, widths)))
    print(line(header))
    print("  ".join("-" * w for w in widths))
    for r in rows:
        print(line(r))


def comparison_table(title, pairs, results, scenarios, variants):
    """Gates and mean proving time of each variant against its reference, per scenario."""
    rows = []
    for variant, reference in pairs:
        if variant not in variants or reference not in variants:
            continue
        for scenario in scenarios:
            g, t = results[f"{variant}/{scenario}"]
            g_ref, t_ref = results[f"{reference}/{scenario}"]
            p, p_ref = statistics.mean(t["prove"]) * 1000, statistics.mean(t_ref["prove"]) * 1000
            rows.append([f"{variant} vs {reference}", scenario, f"{g_ref:,}", f"{g:,}", f"{g / g_ref:.2f}x",
                         f"{p_ref:.1f}", f"{p:.1f}", f"{p / p_ref:.2f}x"])
    if rows:
        print()
        print(title)
        print_table(["Comparison", "Scenario", "Gates (ref)", "Gates", "Gates ratio",
                     "Prove ms (ref)", "Prove ms", "Prove ratio"], rows)


def fmt(samples):
    mean = statistics.mean(samples) * 1000
    std = statistics.stdev(samples) * 1000 if len(samples) > 1 else 0.0
    return f"{mean:9.1f} ± {std:6.1f} ms"


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("scenarios", nargs="*", metavar="SCENARIO",
                    help=f"any of {', '.join(SCENARIOS)} (default: all)")
    ap.add_argument("--variants", nargs="+", default=VARIANTS, metavar="V",
                    help=f"any of {', '.join(VARIANTS)} (default: all)")
    ap.add_argument("--runs", type=int, default=10, help="executions per circuit (default: 10)")
    args = ap.parse_args()
    for scenario in args.scenarios:
        if scenario not in SCENARIOS:
            ap.error(f"unknown scenario {scenario!r}, choose from {', '.join(SCENARIOS)}")
    for variant in args.variants:
        if variant not in VARIANTS:
            ap.error(f"unknown variant {variant!r}, choose from {', '.join(VARIANTS)}")
    scenarios = args.scenarios or SCENARIOS
    variants = [v for v in VARIANTS if v in args.variants]

    results = {}
    for scenario in scenarios:
        for variant in variants:
            label = f"{variant}/{scenario}"
            print(f"Benchmarking {label} ({args.runs} runs)...", flush=True)
            results[label] = benchmark(IMPLEMENTATIONS / variant / scenario, args.runs)

    print()
    print(f"{'Circuit':<24}{'Gates':>10}  {'Witness (nargo execute)':>24}"
          f"  {'Proof (bb prove)':>20}  {'Verify (bb verify)':>20}")
    for label, (n_gates, t) in results.items():
        print(f"{label:<24}{n_gates:>10,}  {fmt(t['execute']):>24}"
              f"  {fmt(t['prove']):>20}  {fmt(t['verify']):>20}")

    comparison_table("ISO 18013-5 versions vs their counterparts", ISO_PAIRS, results, scenarios, variants)
    comparison_table("Longfellow vs the ISO-compliant versions", LONGFELLOW_PAIRS, results, scenarios,
                     variants)


if __name__ == "__main__":
    main()
