# This script contains the main logic for the testbed. The implementations
# folder on the root of this repository contains the various implementations 
# of the ZKPs. This testbed will run each variation, and compare the results.

import os
import subprocess
import time

from interface import (
    print_footer,
    print_header,
    print_summary_table,
    print_variation_footer,
    print_variation_header,
)

# Number of executions to average for each test
EXECUTIONS = 10
# Root of the implementations folder (relative to this script)
IMPLEMENTATIONS_DIR = os.path.join(os.path.dirname(__file__), "..", "implementations")

VARIATIONS = [
    "base",
    "sha256",
    "sha512",
    "mimc",
    "poseidon",
]

SCENARIOS = [
    "age",
    "int",
    "nationality",
    "str"
]

def generate_proof(variation: str):
    """Generate a proof for the specified implementation."""
    all_times = []
    all_sizes = []

    # Iterate each scenario and generate a proof for it
    for scenario in SCENARIOS:
        circuit_dir = os.path.join(IMPLEMENTATIONS_DIR, variation, scenario)
        circuit_file = os.path.join("target", f"{scenario}.json")
        witness_file = os.path.join("target", f"{scenario}.gz")
        proof_dir = os.path.join("target", "proof")

        # Ensure the proof output directory exists
        os.makedirs(os.path.join(circuit_dir, proof_dir), exist_ok=True)

        # Clear any content in the target directory before running
        for file in os.listdir(os.path.join(circuit_dir, "target")):
            file_path = os.path.join(circuit_dir, "target", file)
            if os.path.isfile(file_path):
                os.remove(file_path)
        
        # Run the nargo compile and execute commands to generate the circuit and witness files
        compile_cmd = ["nargo", "compile"]
        execute_cmd = ["nargo", "execute"]

        print(f"  Compiling circuit for scenario: {scenario}...")

        compile_result = subprocess.run(
            compile_cmd,
            cwd=circuit_dir,
            capture_output=True,
            text=True,
            check=False,
        )
        if compile_result.returncode != 0:
            print(f"  ✗ Compilation failed: {compile_result.stderr.strip()}")
            continue

        execute_result = subprocess.run(
            execute_cmd,
            cwd=circuit_dir,
            capture_output=True,
            text=True,
            check=False,
        )

        if execute_result.returncode != 0:
            print(f"  ✗ Witness generation failed: {execute_result.stderr.strip()}")
            continue

        cmd = ["bb", "prove", "-b", circuit_file, "-w", witness_file, "-o", proof_dir]

        print(f"  Generating proof for scenario: {scenario} ({EXECUTIONS} runs)")
        print(f"  Command: {' '.join(cmd)}")

        times = []
        sizes = []
        failed = False
        proof_file = os.path.join(circuit_dir, proof_dir, "proof")
        for i in range(1, EXECUTIONS + 1):
            print(f"  Run {i}/{EXECUTIONS}...", end="\r")
            start = time.perf_counter()
            result = subprocess.run(cmd, cwd=circuit_dir, capture_output=True, text=True, check=False)
            elapsed = time.perf_counter() - start
            if result.returncode != 0:
                print(f"  ✗ Run {i} failed: {result.stderr.strip()}")
                failed = True
                break
            times.append(elapsed)
            if os.path.exists(proof_file):
                sizes.append(os.path.getsize(proof_file))

        if not failed:
            avg_time = sum(times) / len(times)
            print(f"  ✓ Avg proof time over {EXECUTIONS} runs: {avg_time:.3f}s")
            if sizes:
                avg_size = sum(sizes) / len(sizes)
                print(f"  ✓ Avg proof size: {avg_size:.0f} bytes ({avg_size / 1024:.2f} KB)")
            all_times.extend(times)
            all_sizes.extend(sizes)
        print()

    return {
        "proof_time": sum(all_times) / len(all_times) if all_times else None,
        "proof_size": sum(all_sizes) / len(all_sizes) if all_sizes else None,
    }

def verify_proof(variation: str):
    """Verify a proof for the specified implementation."""
    all_times = []

    # Iterate each scenario and generate a proof for it
    for scenario in SCENARIOS:
        circuit_dir = os.path.join(IMPLEMENTATIONS_DIR, variation, scenario)
        circuit_file = os.path.join("target", f"{scenario}.json")
        proof_dir = os.path.join("target", "proof")

        # Ensure the proof output directory exists
        os.makedirs(os.path.join(circuit_dir, proof_dir), exist_ok=True)

        print(f"  Writing verification key for scenario: {scenario}...")

        # Run the write_vk command to generate the verification key
        vk_cmd = ["bb", "write_vk", "-b", circuit_file, "-o", proof_dir]
        result = subprocess.run(vk_cmd, cwd=circuit_dir, capture_output=True, text=True, check=False)
        if result.returncode != 0:
            print(f"  ✗ Failed to write verification key: {result.stderr.strip()}")
            continue

        proof_file = os.path.join(circuit_dir, proof_dir, "proof")
        vk_file = os.path.join(circuit_dir, proof_dir, "vk")
        public_inputs = os.path.join(circuit_dir, proof_dir, "public_inputs")

        if not os.path.exists(proof_file) or not os.path.exists(vk_file):
            print(f"  ✗ Proof or verification key not found for scenario: {scenario}")
            continue

        cmd = ["bb", "verify", "-k", vk_file, "-p", proof_file, "-i", public_inputs]

        print(f"  Verifying proof for scenario: {scenario} ({EXECUTIONS} runs)")
        print(f"  Command: {' '.join(cmd)}")

        times = []
        failed = False
        for i in range(1, EXECUTIONS + 1):
            print(f"  Run {i}/{EXECUTIONS}...", end="\r")
            start = time.perf_counter()
            result = subprocess.run(cmd, cwd=circuit_dir, capture_output=True, text=True, check=False)
            elapsed = time.perf_counter() - start
            if result.returncode != 0:
                print(f"  ✗ Run {i} failed: {result.stderr.strip()}")
                failed = True
                break
            times.append(elapsed)

        if not failed:
            avg_time = sum(times) / len(times)
            print(f"  ✓ Avg verification time over {EXECUTIONS} runs: {avg_time:.3f}s")
            all_times.extend(times)
        print()

    return {
        "verification_time": sum(all_times) / len(all_times) if all_times else None,
    }

def run_base():
    """Run the base implementation of the testbed."""
    result = {"variation": "base", "proof_time": None, "proof_size": None, "verification_time": None}
    result.update(generate_proof("base"))
    result.update(verify_proof("base"))
    return result

def run_sha256():
    """Run the sha256 implementation of the testbed."""
    result = {"variation": "sha256", "proof_time": None, "proof_size": None, "verification_time": None}
    result.update(generate_proof("sha256"))
    result.update(verify_proof("sha256"))
    return result

def run_sha512():
    """Run the sha512 implementation of the testbed."""
    result = {"variation": "sha512", "proof_time": None, "proof_size": None, "verification_time": None}
    result.update(generate_proof("sha512"))
    result.update(verify_proof("sha512"))
    return result

def run_mimc():
    """Run the mimc implementation of the testbed."""
    result = {"variation": "mimc", "proof_time": None, "proof_size": None, "verification_time": None}
    result.update(generate_proof("mimc"))
    result.update(verify_proof("mimc"))
    return result

def run_poseidon():
    """Run the poseidon implementation of the testbed."""
    result = {"variation": "poseidon", "proof_time": None, "proof_size": None, "verification_time": None}
    result.update(generate_proof("poseidon"))
    result.update(verify_proof("poseidon"))
    return result

def run():
    """Main function to run the testbed."""
    print_header(VARIATIONS)

    total = len(VARIATIONS)
    summary = []
    for i, variation in enumerate(VARIATIONS, start=1):
        print_variation_header(variation, i, total)
        if variation == "base":
            summary.append(run_base())
        if variation == "sha256":
            summary.append(run_sha256())
        if variation == "sha512":
            summary.append(run_sha512())
        if variation == "mimc":
            summary.append(run_mimc())
        if variation == "poseidon":
            summary.append(run_poseidon())
        print_variation_footer(variation)

    print_summary_table(summary)
    print_footer(total)


if __name__ == "__main__":
    run()
