#!/usr/bin/env python3
"""Writes the inputs of every circuit from the issued credentials.

  .venv/bin/python generate.py [VARIANT ...]

For each variant (default: all) and scenario, writes in the circuit's directory
  Prover.toml                         the inputs of holder1, for nargo execute
  inputs_<variant>_<scenario>.dart    the inputs of holder1 to holder4 (runs 1 to 4), flattened in
                                      the order of the circuit's ABI, for the testing application
and collects them for the testing application in ../scenarios/mdl:
  circuits/<variant>_<scenario>.json  the compiled circuits
  inputs/inputs_<scenario>.dart       the runs of every variant
Requires nargo (to compile the circuits for their ABI, and for the Poseidon digests).
"""

import argparse
import json
import shutil
import subprocess
import sys
from pathlib import Path

from holders import HOLDERS, SCENARIOS
from inputs import IMPLEMENTATIONS, Credential

VARIANTS = {
    "base": "base",
    "sha256-iso": "iso/sha256",
    "sha512-iso": "iso/sha512",
    "poseidon-iso": "iso/poseidon",
    "longfellow": "longfellow",
    "vega": "vega",
}


def abi(package):
    subprocess.run(["nargo", "compile"], cwd=package, check=True, capture_output=True)
    return json.loads((package / "target" / f"{package.name}.json").read_text())["abi"]["parameters"]


def flatten(v):
    return [v] if isinstance(v, int) else [x for e in v for x in flatten(e)]


def toml(inputs, params):
    def value(v):
        return f'"{v}"' if isinstance(v, int) else "[" + ", ".join(str(x) for x in flatten(v)) + "]"
    return "".join(f"{p['name']} = {value(inputs[p['name']])}\n" for p in params)


APP = Path(__file__).resolve().parent.parent / "scenarios" / "mdl"


def dart_runs(runs, params, name):
    return "".join(
        f'  {{\n    "file": "{name}",\n    "executions": 250,\n    "run": {run},\n'
        f'    "inputs": [{", ".join(str(x) for p in params for x in flatten(inputs[p["name"]]))}]\n  }},\n'
        for run, inputs in runs)


def dart(body):
    return f"final inputs = [\n{body}];\n"


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("variants", nargs="*", metavar="VARIANT", help=", ".join(VARIANTS))
    variants = ap.parse_args().variants or list(VARIANTS)
    for v in variants:
        if v not in VARIANTS:
            ap.error(f"unknown variant {v!r}")
    collected = {scenario: [] for scenario in SCENARIOS}
    (APP / "circuits").mkdir(parents=True, exist_ok=True)
    (APP / "inputs").mkdir(parents=True, exist_ok=True)
    for variant in variants:
        for scenario in SCENARIOS:
            package = IMPLEMENTATIONS / VARIANTS[variant] / scenario
            params = abi(package)
            runs = [(i + 1, Credential(h["name"], scenario).inputs(variant))
                    for i, h in enumerate(HOLDERS)]
            missing = {p["name"] for p in params} - set(runs[0][1])
            if missing:
                sys.exit(f"{variant}/{scenario}: no value for {sorted(missing)}")
            (package / "Prover.toml").write_text(toml(runs[0][1], params))
            name = f"{variant.replace('-', '_')}_{scenario}"
            body = dart_runs(runs, params, name)
            (package / f"inputs_{name}.dart").write_text(dart(body))
            collected[scenario].append(body)
            shutil.copy(package / "target" / f"{scenario}.json", APP / "circuits" / f"{name}.json")
            print(f"{variant}/{scenario}: Prover.toml and {len(runs)} runs")
    if variants == list(VARIANTS):
        for scenario, bodies in collected.items():
            (APP / "inputs" / f"inputs_{scenario}.dart").write_text(dart("".join(bodies)))


if __name__ == "__main__":
    main()
