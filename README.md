# Verifiable ZKP

A proof of concept exploring **attribute verification inside Zero-Knowledge Proofs (ZKPs)** using different hash functions. The core idea is that a trusted source (e.g. an identity document issuer) provides a hash of a private attribute. The ZKP circuit receives that hash as a public input, recomputes it internally over the private attribute, and asserts they match — proving knowledge of the attribute without revealing it.

This repository was developed in the context of the **DISSECT** project.

---

## Overview

Five variations are implemented, differing in the hash function used to bind the private attribute:

| Variation | Hash Function | Notes |
|-----------|--------------|-------|
| `base` | None | No hash binding; attribute is not verified against an external commitment |
| `sha256` | SHA-256 | Supported by the ISO/IEC 18013-5 mDoc standard |
| `sha512` | SHA-512 | Supported by the ISO/IEC 18013-5 mDoc standard |
| `mimc` | MiMC BN254 | ZKP-friendly hash function; low circuit complexity |
| `poseidon` | Poseidon | ZKP-friendly hash function; widely used in ZK protocols |

Each variation includes four **scenarios** emulating identity-related attribute proofs:

| Scenario | Description |
|----------|-------------|
| `age` | Prove that a date of birth corresponds to an age above a threshold |
| `int` | Prove that a private integer satisfies a comparison (e.g. `x > y`) |
| `nationality` | Prove that a nationality code belongs to an allowed list |
| `str` | Prove that a substring appears within a larger private string (e.g. an address) |

---

## Project Structure

```
verifiable-zkp/
├── implementations/
│   ├── base/               # No hash binding
│   │   ├── age/
│   │   ├── int/
│   │   ├── nationality/
│   │   └── str/
│   ├── sha256/             # SHA-256 hash binding
│   │   ├── age/
│   │   ├── int/
│   │   ├── nationality/
│   │   └── str/
│   ├── sha512/             # SHA-512 hash binding
│   │   ├── age/
│   │   ├── int/
│   │   ├── nationality/
│   │   └── str/
│   ├── mimc/               # MiMC BN254 hash binding
│   │   ├── age/
│   │   ├── int/
│   │   ├── nationality/
│   │   └── str/
│   └── poseidon/           # Poseidon hash binding
│       ├── age/
│       ├── int/
│       ├── nationality/
│       └── str/
│
│   Each scenario directory contains:
│       ├── src/main.nr     # Noir circuit
│       ├── Nargo.toml      # Noir package manifest
│       ├── Prover.toml     # Proof inputs
│       ├── bytes.sh        # Helper script to compute inputs and hash
│       └── target/         # Compiled artifacts and proofs
│
└── testbed/
    ├── run.py              # Main testbed runner
    └── interface.py        # CLI output formatting
```

---

## Prerequisites

- [Noir](https://noir-lang.org/) (`nargo`) — circuit language and compiler
- [Barretenberg](https://github.com/AztecProtocol/aztec-packages/tree/master/barretenberg) (`bb`) — proving backend
- Python 3.8+

---

## Running the Testbed

The testbed benchmarks all five variations across all four scenarios, reporting average proof generation time, proof size, and verification time over **10 runs** per scenario.

```bash
python3 testbed/run.py
```

The testbed will:
1. Compile and execute each circuit to generate a witness
2. Run `bb prove` 10 times per scenario and average the proof generation time and proof size
3. Run `bb verify` 10 times per scenario and average the verification time
4. Print a summary table comparing all variations

### Example Output

```
============================================================
               Verifiable ZKP Testbed
                  DISSECT Project
============================================================
  Registered variations: base, sha256, sha512, mimc, poseidon
------------------------------------------------------------

  [1/5] Running: BASE
  ----------------------------------------------------------
  Compiling circuit for scenario: age...
  Generating proof for scenario: age (10 runs)
  ✓ Avg proof time over 10 runs: 1.243s
  ✓ Avg proof size: 2144 bytes (2.09 KB)
  ...
  ✓ Completed: base

  ...

------------------------------------------------------------
  All 5 variation(s) completed successfully.
============================================================
```

---

## How the Hash Binding Works

For hash-based variations, each circuit receives:
- A **private** attribute (e.g. date of birth)
- A **public** salt
- A **public** hash commitment (produced externally by a trusted source)

Inside the circuit:
1. The salt is prepended to the attribute
2. The hash function is applied
3. The result is asserted to equal the provided commitment

This ensures the prover cannot use an arbitrary attribute — they must use the exact one committed to by the trusted source.

The `bytes.sh` script in each scenario directory can be used to compute the correct inputs and hash commitment to populate `Prover.toml`.


## Running a Single Circuit

Each scenario can be run independently. For example, to run the SHA-256 age scenario:

```bash
cd implementations/sha256/age

# 1. Compile the circuit
nargo compile

# 2. Execute the circuit (generates the witness)
nargo execute

# 3. Generate the proof
bb prove -b target/age.json -w target/age.gz -o target/proof

# 4. Write the verification key
bb write_vk -b target/age.json -o target/proof

# 5. Verify the proof
bb verify -k target/proof/vk -p target/proof/proof -i target/proof/public_inputs
```
