#!/usr/bin/env python3
"""Compares the circuit variants on this machine, in the four mDL scenarios.

The variants are base (the predicate only), the ISO/IEC 18013-5 item digests sha256-iso,
sha512-iso and poseidon-iso (the latter for comparison only), and the ports of longfellow and vega,
all run on the same credentials (../credentials). Every variant is compared with base (the cost
of authentication), longfellow with the ISO-compliant digests (sha256-iso and sha512-iso), and vega
with longfellow and sha256-iso. For each circuit it reports the number of gates (bb gates) and the
average time to generate the witness (nargo execute), to build the circuit from the ACIR
bytecode (bb gates), to generate the zero-knowledge proof (bb prove, which includes building the
circuit) and to verify it (bb verify), on holder1's inputs (Prover.toml). The circuits are copied to a temporary
directory, so the target/ folders in the repository are left untouched.

Writes the raw measurements to tests/comparison-results.json and the report to
tests/comparison-results.md; --report rebuilds the report from the JSON without benchmarking.

Usage: python3 tests/comparison.py [SCENARIO ...] [--variants V ...] [--runs N]
       python3 tests/comparison.py --report
       SCENARIO is one of age, rental, residence, veteran (default: all of them)
       V is any of the variants below (default: all of them)
Requires: nargo and bb on the PATH.
"""

import argparse
import datetime
import json
import platform
import shutil
import statistics
import subprocess
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
IMPLEMENTATIONS = ROOT / "implementations"
SCENARIOS = ["age", "rental", "residence", "veteran"]
VARIANTS = ["base", "sha256-iso", "sha512-iso", "poseidon-iso", "longfellow", "vega"]
# directory of each variant under implementations/
VARIANT_DIR = {
    "base": "base", "sha256-iso": "iso/sha256", "sha512-iso": "iso/sha512",
    "poseidon-iso": "iso/poseidon", "longfellow": "longfellow", "vega": "vega",
}
# Comparison tables printed at the end, as (variant, reference) pairs. poseidon-iso uses a digest
# algorithm that ISO 18013-5 does not allow, so longfellow is compared only with the ISO-compliant
# digests.
BASE_PAIRS = [(v, "base") for v in VARIANTS[1:]]
VARIANT_LABEL = {"base": "base (predicate only)"}
RESULTS_JSON = ROOT / "tests" / "comparison-results.json"
# Barretenberg's verifier target: UltraHonk with zero knowledge and Poseidon2 transcripts (the
# default of bb 6; the -no-zk targets would drop zero knowledge)
TARGET = "noir-recursive"
RESULTS_MD = ROOT / "tests" / "comparison-results.md"
LONGFELLOW_PAIRS = [("longfellow", "sha256-iso"), ("longfellow", "sha512-iso")]
VEGA_PAIRS = [("vega", "longfellow"), ("vega", "sha256-iso")]


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
    elapsed, out = run(["bb", "gates", "-b", str(json_path)], cwd)
    info = json.loads(out[out.index("{"):])["functions"][0]
    return info["circuit_size"], info["acir_opcodes"], elapsed


def benchmark(src, runs):
    with tempfile.TemporaryDirectory() as tmp:
        # Mirror implementations/ so that relative path dependencies (../lib, ../../iso/common/lib) resolve
        work = Path(tmp) / src.relative_to(IMPLEMENTATIONS)
        for d in [src] + path_dependencies(src):
            shutil.copytree(d, Path(tmp) / d.relative_to(IMPLEMENTATIONS),
                            ignore=shutil.ignore_patterns("target"), dirs_exist_ok=True)
        name = package_name(work)
        circuit, witness = work / "target" / f"{name}.json", work / "target" / f"{name}.gz"

        run(["nargo", "compile"], work)
        n_gates, opcodes, _ = gates(circuit, work)
        run(["bb", "write_vk", "-b", str(circuit), "-o", "target", "-t", TARGET], work)

        times = {"execute": [], "build": [], "prove": [], "verify": []}
        for _ in range(runs):
            times["execute"].append(run(["nargo", "execute"], work)[0])
            times["build"].append(gates(circuit, work)[2])
            times["prove"].append(
                run(["bb", "prove", "-b", str(circuit), "-w", str(witness), "-k", "target/vk",
                     "-o", "target", "-t", TARGET], work)[0])
            times["verify"].append(
                run(["bb", "verify", "-k", "target/vk", "-p", "target/proof",
                     "-i", "target/public_inputs", "-t", TARGET], work)[0])
        return {"gates": n_gates, "opcodes": opcodes, "times": times}


# ---------------- report ----------------

def ms(samples):
    return statistics.mean(samples) * 1000


def median_ms(samples):
    return statistics.median(samples) * 1000


def short_time(samples):
    t = ms(samples)
    return f"{t / 1000:.2f} s" if t >= 1000 else f"{t:.0f} ms"


def short_gates(n):
    return f"{n / 1000:.1f}k" if n < 100_000 else f"{n / 1000:.0f}k"


def mean_sd(samples):
    sd = statistics.stdev(samples) * 1000 if len(samples) > 1 else 0.0
    return f"{ms(samples):.1f} ± {sd:.1f}"


def md_table(header, rows, align=None):
    align = align or ["l"] + ["r"] * (len(header) - 1)
    sep = ["---:" if a == "r" else "---" for a in align]
    return "\n".join("| " + " | ".join(str(c) for c in r) + " |" for r in [header, sep] + rows)


def comparison_rows(pairs, results, scenarios):
    rows = []
    for variant, reference in pairs:
        for scenario in scenarios:
            a, b = results.get(f"{variant}/{scenario}"), results.get(f"{reference}/{scenario}")
            if a and b:
                pa, pb = ms(a["times"]["prove"]), ms(b["times"]["prove"])
                qa, qb = median_ms(a["times"]["prove"]), median_ms(b["times"]["prove"])
                rows.append([f"{variant} vs {reference}", scenario, f"{b['gates']:,}",
                             f"{a['gates']:,}", f"{a['gates'] / b['gates']:.2f}x", f"{pb:.0f}",
                             f"{pa:.0f}", f"{pa / pb:.2f}x", f"{qa / qb:.2f}x"])
    return rows


def report(data):
    results, meta = data["results"], data["meta"]
    scenarios = [s for s in SCENARIOS if any(k.endswith(f"/{s}") for k in results)]
    variants = [v for v in VARIANTS if any(k.startswith(f"{v}/") for k in results)]
    out = ["# Benchmark results", "",
           f"`tests/comparison.py`, {meta['runs']} runs per circuit, {meta['date']}, "
           f"{meta['machine']}, {meta['nargo']}, bb {meta['bb']}. Inputs: holder1 of "
           "`credentials/` (the same credential in every variant).", "",
           "## Summary", "",
           "Gates (`bb gates`) and mean proving time (`bb prove`) per variant and scenario. "
           "The medians are in the tables below; they differ from the means only where a run was "
           "slow.", ""]
    out.append(md_table(["Variant"] + scenarios, [
        [VARIANT_LABEL.get(v, v)] + [
            f"{short_gates(results[f'{v}/{s}']['gates'])} · {short_time(results[f'{v}/{s}']['times']['prove'])}"
            if f"{v}/{s}" in results else "" for s in scenarios]
        for v in variants], ["l"] + ["r"] * len(scenarios)))
    verify = [statistics.median(r["times"]["verify"]) * 1000 for r in results.values()]
    out += ["", f"Verification takes {min(verify):.0f} to {max(verify):.0f} ms (median per "
            "circuit) for every circuit.",
            "", "## Every circuit", "",
            "Times are the mean ± standard deviation in ms, and the median of *Prove*. Each run "
            "has four steps:", "",
            "- **Witness** (`nargo execute`): runs the circuit on the holder's inputs and "
            "computes the witness, the values of every wire. It also checks every constraint, "
            "so invalid inputs fail here.",
            "- **Build** (`bb gates`): builds the UltraHonk circuit from Noir's ACIR bytecode, "
            "with no proof. It is measured on its own to show its share of *Prove*.",
            "- **Prove** (`bb prove`): builds the circuit again and generates the "
            "zero-knowledge proof from the witness. It includes *Build*, as a mobile prover "
            "builds the circuit for every proof. With *Witness*, this is the holder's cost.",
            "- **Verify** (`bb verify`): checks the proof against the verification key and the "
            "public inputs. This is the verifier's cost.", "",
            "*Gates* is the `circuit_size` of `bb gates`. Its meaning depends on the Barretenberg "
            "version (bb 6 counts a block of about 15,300 rows whenever SHA-256 is used, which "
            "bb 0.84 did not), so gates are comparable only within one toolchain. The prover pads "
            "the circuit to a power of two, so circuits in the same power of two take similar "
            "times.", ""]
    out.append(md_table(
        ["Circuit", "Gates", "ACIR opcodes", "Witness", "Build", "Prove", "Prove median",
         "Verify"],
        [[k, f"{r['gates']:,}", f"{r['opcodes']:,}", mean_sd(r["times"]["execute"]),
          mean_sd(r["times"]["build"]), mean_sd(r["times"]["prove"]),
          f"{median_ms(r['times']['prove']):.1f}", mean_sd(r["times"]["verify"])]
         for k, r in results.items()]))
    header = ["Comparison", "Scenario", "Gates (ref)", "Gates", "Gates ratio", "Prove ms (ref)",
              "Prove ms", "Prove ratio", "Prove ratio (median)"]
    for title, pairs in [("Every variant vs base (the cost of authentication)", BASE_PAIRS),
                         ("Longfellow vs the ISO-compliant digests", LONGFELLOW_PAIRS),
                         ("VegaSC vs Longfellow and sha256-iso", VEGA_PAIRS)]:
        rows = comparison_rows(pairs, results, scenarios)
        if rows:
            out += ["", f"## {title}", "",
                    "Prove ms are means; the ratios are of the means and of the medians.", "",
                    md_table(header, rows)]
    return "\n".join(out) + "\n"


def tool_version(cmd):
    try:
        return subprocess.run(cmd, capture_output=True, text=True).stdout.strip().splitlines()[0]
    except (OSError, IndexError):
        return "unknown"


def machine():
    cpu = platform.processor()
    if platform.system() == "Darwin":
        cpu = tool_version(["sysctl", "-n", "machdep.cpu.brand_string"])
    return f"{cpu} ({platform.system()} {platform.machine()})"


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("scenarios", nargs="*", metavar="SCENARIO",
                    help=f"any of {', '.join(SCENARIOS)} (default: all)")
    ap.add_argument("--variants", nargs="+", default=VARIANTS, metavar="V",
                    help=f"any of {', '.join(VARIANTS)} (default: all)")
    ap.add_argument("--runs", type=int, default=10, help="executions per circuit (default: 10)")
    ap.add_argument("--report", action="store_true",
                    help="rebuild the report from comparison-results.json without benchmarking")
    args = ap.parse_args()
    if args.report:
        data = json.loads(RESULTS_JSON.read_text())
        RESULTS_MD.write_text(report(data))
        print(f"wrote {RESULTS_MD}")
        return
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
            results[label] = benchmark(IMPLEMENTATIONS / VARIANT_DIR[variant] / scenario, args.runs)
    # order by variant, then scenario
    results = {f"{v}/{s}": results[f"{v}/{s}"] for v in variants for s in scenarios}
    data = {"meta": {"runs": args.runs, "date": datetime.date.today().isoformat(),
                     "machine": machine(), "nargo": tool_version(["nargo", "--version"]),
                     "bb": tool_version(["bb", "--version"])},
            "results": results}
    RESULTS_JSON.write_text(json.dumps(data, indent=1) + "\n")
    RESULTS_MD.write_text(report(data))
    print(f"wrote {RESULTS_JSON} and {RESULTS_MD}")


if __name__ == "__main__":
    main()
