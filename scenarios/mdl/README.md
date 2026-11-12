# mDL scenarios: compiled circuits and inputs

This directory packages the evaluation's circuits and inputs for running on a mobile device. It
has every variant (`base`, `sha256-iso`, `sha512-iso`, `poseidon-iso`, `longfellow`, `vega`)
in each of the four mDL scenarios (`age`, `rental`, `residence`, `veteran`), with the inputs of
the four test holders. The files are derived from the Noir sources in `implementations/` and the
credentials in `credentials/`. They are generated, not written by hand.

```
scenarios/mdl/
├── circuits/<variant>_<scenario>.json   # 24 compiled circuits (6 variants × 4 scenarios)
└── inputs/inputs_<scenario>.dart        # inputs of every variant and holder, one file per scenario
```

In file names, `-` in a variant name becomes `_` (`sha256-iso` is `sha256_iso`).

## Provenance

Both are produced by `credentials/generate.py`:

- **Circuits.** Each circuit in `implementations/<variant>/<scenario>/` is compiled with
  `nargo compile`. Its output (`target/<scenario>.json`, the ACIR bytecode and the ABI) is copied
  here unchanged. The committed files were compiled with nargo 1.0.0, and the benchmark proves
  them with Barretenberg 6.0.0 (UltraHonk, `noir-recursive` target).
- **Inputs.** `credentials/inputs.py` derives each circuit's inputs from the mDLs in
  `credentials/holders/`, issued with pyMDOC-CBOR. Depending on the variant they are:
  - the `IssuerSignedItemBytes` of the requested element, as issued;
  - its digest (SHA-256 as in the MSO; SHA-512 and Poseidon recomputed over the same bytes);
  - for `longfellow` and `vega`, the MSO, the issuer and device signatures and the session
    transcript;
  - the scenario's public parameters (`credentials/holders.py`).

  `credentials/README.md` describes how the credentials were issued and the only two
  transformations applied: ECDSA low-s normalization, and the SHA-512 and Poseidon digests.

The inputs here are the same values the desktop benchmark uses. Holder 1's run of each circuit
equals the `Prover.toml` in its directory, which `tests/comparison.py` executes. The other three
holders are the additional runs.

## Reproducing

With nargo 1.0.0 installed:

```
cd credentials
python3 -m venv .venv && .venv/bin/pip install -r requirements.txt
.venv/bin/python generate.py
git status scenarios/mdl
```

The generation is deterministic. On the committed credentials it reproduces every file in this
directory byte for byte, so `git status` reports no changes. A different nargo version gives
different circuit files: the ACIR format and its gate counts change between versions (see
`tests/comparison-results.md`).

## Input format

Each `inputs_<scenario>.dart` declares one list. It has an entry per variant and holder, 24 per
scenario:

```dart
final inputs = [
  {
    "file": "sha256_iso_age",     // circuit in circuits/, without the extension
    "executions": 250,            // proofs to generate per run
    "run": 1,                     // holder (1 to 4)
    "inputs": [217, 3, 236, ...]  // all inputs, flattened in the order of the circuit's ABI
  },
  ...
];
```

The flattening follows the ABI in the circuit file. Each parameter is written in declaration
order, and arrays and nested arrays are flattened row by row. A prover can therefore map the list
back to named inputs using only the circuit file.
