"""Helpers for the soundness tests (implementations/*/test_soundness.py): fresh credentials issued
by pyMDOC-CBOR with the committed test PKI, and execution of a circuit on (tampered) inputs."""

import json
import subprocess
import tempfile
from pathlib import Path

from holders import HOLDERS, SCENARIOS
from inputs import IMPLEMENTATIONS, Credential
from issue import issue, load_pki
from present import present

VARIANT_DIR = {
    "base": "base", "sha256-iso": "iso/sha256", "sha512-iso": "iso/sha512",
    "poseidon-iso": "iso/poseidon", "longfellow": "longfellow", "vega": "vega",
}
_tmp = tempfile.TemporaryDirectory()
_count = 0
_compiled = set()  # packages compiled by this process (the sources do not change during a run)


def fresh(holder=0, scenario="age", data=None, status=None, device_key=None):
    """A newly issued credential of HOLDERS[holder] (or with `data` as its namespaces, and `status`
    as the MSO's status entry), presented in `scenario`. Returns its Credential."""
    global _count
    _count += 1
    h = HOLDERS[holder]
    folder = Path(_tmp.name) / f"{h['name']}-{_count}"
    issue(h, folder, load_pki(), data=data, status=status)
    present(folder, scenario, device_key)
    return Credential(h["name"], scenario, folder)


def committed(holder=0, scenario="age"):
    return Credential(HOLDERS[holder]["name"], scenario)


def flatten(v):
    return [v] if isinstance(v, int) else [x for e in v for x in flatten(e)]


def execute(variant, scenario, inputs):
    """Runs the circuit on `inputs`. Returns None if it accepts them, else the failed assertion."""
    package = IMPLEMENTATIONS / VARIANT_DIR[variant] / scenario
    if package not in _compiled:
        subprocess.run(["nargo", "compile"], cwd=package, check=True, capture_output=True)
        _compiled.add(package)
    params = json.loads((package / "target" / f"{scenario}.json").read_text())["abi"]["parameters"]
    toml = "".join(
        f'{p["name"]} = '
        + (f'"{inputs[p["name"]]}"' if isinstance(inputs[p["name"]], int)
           else "[" + ", ".join(str(x) for x in flatten(inputs[p["name"]])) + "]") + "\n"
        for p in params)
    prover = package / "ProverTest.toml"
    prover.write_text(toml)
    try:
        res = subprocess.run(["nargo", "execute", "-p", "ProverTest"], cwd=package,
                             capture_output=True, text=True)
    finally:
        prover.unlink()
    if res.returncode == 0:
        return None
    out = res.stdout + res.stderr
    for line in out.splitlines():
        if "Assertion failed:" in line:
            return line.split("Assertion failed:", 1)[1].strip().strip("'\"").rstrip(".")
    return out.strip().splitlines()[-1]


def report(tests):
    """Runs (name, function returning (got, expected)) pairs; returns the number of failures."""
    failed = 0
    for name, run in tests:
        got, expected = run()
        ok = got == expected
        failed += not ok
        show = lambda r: "accepted" if r is None else f"rejected ({r})"
        print(f"{'PASS' if ok else 'FAIL'}  {name}: {show(got)}"
              + ("" if ok else f", expected {show(expected)}"), flush=True)
    return failed
